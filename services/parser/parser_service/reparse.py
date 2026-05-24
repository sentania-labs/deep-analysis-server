"""Force-reparse endpoints — delete parsed matches so the parser
re-processes them from raw files on the next backfill cycle.

Routes:
- DELETE /parser/matches — caller's own matches (per-agent scope)
- POST /parser/me/reparse — caller's whole account, rate-limited
- DELETE /parser/admin/matches/{user_id} — admin deletes for a user
- DELETE /parser/admin/matches — admin nuclear: all matches
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from parser_service.db import get_session
from parser_service.deps import AuthenticatedUser, require_admin, require_user
from parser_service.models import Game, GamePlayer, GameState, Match

_log = logging.getLogger("parser.reparse")

router = APIRouter()

# Self-service cooldown: a user can only reparse their full account
# once per hour. Hardcoded — promote to a tunable in a follow-up if
# operators want to tune it.
_USER_REPARSE_COOLDOWN_SECONDS = 3600


def _now() -> datetime:
    """Indirection so tests can mock the clock."""
    return datetime.now(UTC)


class DeletedCountResponse(BaseModel):
    deleted_count: int


# Atomic check-and-set: INSERT a fresh row, or on conflict, UPDATE
# only if the existing row has aged past the cooldown. This single
# statement is the atomicity boundary — concurrent callers serialize
# on the row lock. ``RETURNING`` yields a row only when the INSERT
# applied or the UPDATE's WHERE passed; an empty result means the
# gate was held by a still-fresh existing row.
_USER_REPARSE_CAS_SQL = text(
    """
    INSERT INTO parser.user_reparse_cooldown (user_id, last_reparse_at)
    VALUES (:user_id, :now)
    ON CONFLICT (user_id) DO UPDATE
        SET last_reparse_at = :now
        WHERE parser.user_reparse_cooldown.last_reparse_at < :cutoff
    RETURNING last_reparse_at
    """
)

# Follow-up read used only on the rate-limited path to surface the
# existing stamp for the retry-at message. Runs as a separate
# statement so it sees the committed state of the row (a same-statement
# SELECT in a CTE shares the INSERT's snapshot and can't see the row
# under concurrent contention — that read would correctly return
# empty for caller 2 even though the row clearly exists).
_USER_REPARSE_EXISTING_SQL = text(
    "SELECT last_reparse_at FROM parser.user_reparse_cooldown WHERE user_id = :user_id"
)


async def _try_acquire_reparse_slot(
    db: AsyncSession,
    user_id: int,
    now: datetime,
    cooldown_seconds: int,
) -> tuple[bool, datetime]:
    """Atomically try to acquire the per-user reparse slot.

    Returns ``(acquired, last_reparse_at)``. When ``acquired`` is
    ``True`` the caller may proceed and ``last_reparse_at`` equals
    ``now``. When ``False`` the caller is rate-limited and
    ``last_reparse_at`` is the existing stamp that blocked them.
    """
    cutoff = now - timedelta(seconds=cooldown_seconds)
    result = await db.execute(
        _USER_REPARSE_CAS_SQL,
        {"user_id": user_id, "now": now, "cutoff": cutoff},
    )
    row = result.first()
    if row is not None:
        return True, row.last_reparse_at
    # CAS failed — gate is held. Read back the existing stamp so the
    # caller can build a retry-at message. Cannot return None here:
    # a failed UPDATE implies a row exists (otherwise the INSERT
    # branch would have applied and RETURNING would be non-empty).
    existing = await db.execute(_USER_REPARSE_EXISTING_SQL, {"user_id": user_id})
    last = existing.scalar_one()
    return False, last


def _parse_iso_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


@router.post("/parser/me/reparse", response_model=DeletedCountResponse)
async def self_service_reparse(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> DeletedCountResponse:
    """User self-service: reparse all of the caller's matches.

    Rate-limited to one call per ``_USER_REPARSE_COOLDOWN_SECONDS`` per
    user. On rate-limit hit, returns 429 with a structured detail
    payload the web layer renders as a friendly retry-at message.
    """
    now = _now()
    acquired, last = await _try_acquire_reparse_slot(
        db, user.user_id, now, _USER_REPARSE_COOLDOWN_SECONDS
    )
    if not acquired:
        elapsed = (now - last).total_seconds()
        remaining = max(int(_USER_REPARSE_COOLDOWN_SECONDS - elapsed), 0)
        retry_at_dt = last + timedelta(seconds=_USER_REPARSE_COOLDOWN_SECONDS)
        _log.info(
            "parser.reparse.user_rate_limited",
            extra={
                "user_id": user.user_id,
                "retry_after_seconds": remaining,
            },
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limited",
                "retry_after_seconds": remaining,
                "retry_at": retry_at_dt.isoformat(),
            },
        )

    count = await _delete_matches_for_user(db, user.user_id, None, None, agent_id=None)
    _log.info(
        "parser.reparse.user_self_service",
        extra={"user_id": user.user_id, "deleted_count": count},
    )
    return DeletedCountResponse(deleted_count=count)


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
        "parser.reparse.user",
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
        "parser.reparse.admin_user",
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
        "parser.reparse.admin_all",
        extra={"deleted_count": count},
    )
    return DeletedCountResponse(deleted_count=count)


def _validate_uuid(value: str, field: str) -> None:
    """Raise 422 if *value* is not a valid UUID."""
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_uuid", "field": field},
        ) from None


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
    if agent_id is not None:
        _validate_uuid(agent_id, "agent_id")

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
        await db.execute(delete(GamePlayer).where(GamePlayer.game_id.in_(game_ids)))
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
        await db.execute(delete(GamePlayer).where(GamePlayer.game_id.in_(game_ids)))
    await db.execute(delete(Game).where(Game.match_id.in_(match_ids)))
    await db.execute(delete(Match).where(Match.id.in_(match_ids)))
    await db.commit()

    return len(match_ids)
