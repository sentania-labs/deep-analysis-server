"""Force-reingest endpoints — delete parsed matches so the parser
re-processes them from raw files on the next backfill cycle.

Routes:
- DELETE /parser/matches — caller's own matches
- DELETE /parser/admin/matches/{user_id} — admin deletes for a user
- DELETE /parser/admin/matches — admin nuclear: all matches
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from parser_service.db import get_session
from parser_service.deps import AuthenticatedUser, require_admin, require_user
from parser_service.models import Game, GameState, Match

_log = logging.getLogger("parser.reingest")

router = APIRouter()


class DeletedCountResponse(BaseModel):
    deleted_count: int


def _parse_iso_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


@router.delete("/parser/matches", response_model=DeletedCountResponse)
async def delete_my_matches(
    after: str | None = Query(default=None, description="ISO date lower bound on played_at"),
    before: str | None = Query(default=None, description="ISO date upper bound on played_at"),
    agent_id: str | None = Query(
        default=None,
        description="Scope deletion to matches uploaded by this agent",
    ),
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> DeletedCountResponse:
    """Delete all parsed matches for the authenticated user.

    Games and game_states are CASCADE-deleted by the FK constraints.
    Optional date filtering on played_at.  When ``agent_id`` is
    provided, only matches whose sha256 was uploaded by that agent
    are deleted.
    """
    count = await _delete_matches_for_user(db, user.user_id, after, before, agent_id=agent_id)
    _log.info(
        "parser.reingest.user",
        extra={"user_id": user.user_id, "agent_id": agent_id, "deleted_count": count},
    )
    return DeletedCountResponse(deleted_count=count)


@router.delete("/parser/admin/matches/{user_id}", response_model=DeletedCountResponse)
async def admin_delete_user_matches(
    user_id: int,
    after: str | None = Query(default=None, description="ISO date lower bound on played_at"),
    before: str | None = Query(default=None, description="ISO date upper bound on played_at"),
    agent_id: str | None = Query(
        default=None,
        description="Scope deletion to matches uploaded by this agent",
    ),
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> DeletedCountResponse:
    """Admin: delete parsed matches for a specific user.

    When ``agent_id`` is provided, only matches whose sha256 was
    uploaded by that agent are deleted.
    """
    count = await _delete_matches_for_user(db, user_id, after, before, agent_id=agent_id)
    _log.info(
        "parser.reingest.admin_user",
        extra={"target_user_id": user_id, "agent_id": agent_id, "deleted_count": count},
    )
    return DeletedCountResponse(deleted_count=count)


@router.delete("/parser/admin/matches", response_model=DeletedCountResponse)
async def admin_delete_all_matches(
    after: str | None = Query(default=None, description="ISO date lower bound on played_at"),
    before: str | None = Query(default=None, description="ISO date upper bound on played_at"),
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> DeletedCountResponse:
    """Admin nuclear: delete ALL parsed matches across all users."""
    count = await _delete_all_matches(db, after, before)
    _log.info(
        "parser.reingest.admin_all",
        extra={"deleted_count": count},
    )
    return DeletedCountResponse(deleted_count=count)


async def _delete_matches_for_user(
    db: AsyncSession,
    user_id: int,
    after_raw: str | None,
    before_raw: str | None,
    *,
    agent_id: str | None = None,
) -> int:
    """Delete matches (and cascaded children) for a single user.

    When *agent_id* is provided, only matches whose ``sha256`` exists
    in ``ingest.user_uploads`` for that agent are deleted.
    """
    after_dt = _parse_iso_dt(after_raw)
    if after_raw is not None and after_dt is None:
        raise HTTPException(status_code=422, detail={"error": "invalid_date", "field": "after"})
    before_dt = _parse_iso_dt(before_raw)
    if before_raw is not None and before_dt is None:
        raise HTTPException(status_code=422, detail={"error": "invalid_date", "field": "before"})

    # Find matching match IDs first, then cascade-delete children
    # explicitly since bulk DELETE doesn't trigger ORM cascades.
    if agent_id is not None:
        # Scope to matches uploaded by this specific agent via the
        # ingest.user_uploads join table.
        from sqlalchemy import text as _text

        sha_rows = await db.execute(
            _text(
                "SELECT sha256 FROM ingest.user_uploads"
                " WHERE agent_registration_id = :agent_id"
                " AND user_id = :user_id"
            ),
            {"agent_id": agent_id, "user_id": user_id},
        )
        agent_shas = [r[0] for r in sha_rows.all()]
        if not agent_shas:
            return 0
        conditions = [Match.user_id == user_id, Match.sha256.in_(agent_shas)]
    else:
        conditions = [Match.user_id == user_id]

    if after_dt is not None:
        conditions.append(Match.played_at >= after_dt)
    if before_dt is not None:
        conditions.append(Match.played_at <= before_dt)

    match_ids_result = await db.execute(select(Match.id).where(*conditions))
    match_ids = [row[0] for row in match_ids_result.all()]

    if not match_ids:
        return 0

    # Delete children first (game_states -> games -> matches)
    game_ids_result = await db.execute(select(Game.id).where(Game.match_id.in_(match_ids)))
    game_ids = [row[0] for row in game_ids_result.all()]

    if game_ids:
        await db.execute(delete(GameState).where(GameState.game_id.in_(game_ids)))
    await db.execute(delete(Game).where(Game.match_id.in_(match_ids)))
    await db.execute(delete(Match).where(Match.id.in_(match_ids)))
    await db.commit()

    return len(match_ids)


async def _delete_all_matches(
    db: AsyncSession,
    after_raw: str | None,
    before_raw: str | None,
) -> int:
    """Delete ALL matches (and cascaded children)."""
    after_dt = _parse_iso_dt(after_raw)
    if after_raw is not None and after_dt is None:
        raise HTTPException(status_code=422, detail={"error": "invalid_date", "field": "after"})
    before_dt = _parse_iso_dt(before_raw)
    if before_raw is not None and before_dt is None:
        raise HTTPException(status_code=422, detail={"error": "invalid_date", "field": "before"})

    conditions = []
    if after_dt is not None:
        conditions.append(Match.played_at >= after_dt)
    if before_dt is not None:
        conditions.append(Match.played_at <= before_dt)

    if conditions:
        match_ids_result = await db.execute(select(Match.id).where(*conditions))
    else:
        match_ids_result = await db.execute(select(Match.id))
    match_ids = [row[0] for row in match_ids_result.all()]

    if not match_ids:
        return 0

    game_ids_result = await db.execute(select(Game.id).where(Game.match_id.in_(match_ids)))
    game_ids = [row[0] for row in game_ids_result.all()]

    if game_ids:
        await db.execute(delete(GameState).where(GameState.game_id.in_(game_ids)))
    await db.execute(delete(Game).where(Game.match_id.in_(match_ids)))
    await db.execute(delete(Match).where(Match.id.in_(match_ids)))
    await db.commit()

    return len(match_ids)
