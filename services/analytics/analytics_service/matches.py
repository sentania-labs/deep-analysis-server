"""Match detail router.

Single-match read endpoint scoped to the calling user. The ownership
check is enforced in the WHERE clause — a user can only fetch matches
they uploaded.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user

router = APIRouter(prefix="/analytics/matches", tags=["matches"])


class GameDetail(BaseModel):
    game_number: int
    winner: str | None = None
    turns: int | None = None


class MatchDetail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    match_id: str
    format_: str | None = Field(default=None, alias="format")
    players: list[str] = Field(default_factory=list)
    played_at: datetime | None = None
    games: list[GameDetail] = Field(default_factory=list)


@router.get("/{match_id}", response_model=MatchDetail)
async def get_match(
    match_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> MatchDetail:
    match_row = (
        await db.execute(
            text(
                """
                SELECT id, format, players, parsed_at
                FROM parser.matches
                WHERE id = :match_id AND user_id = :user_id
                """
            ),
            {"match_id": match_id, "user_id": user.user_id},
        )
    ).one_or_none()
    if match_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "match_not_found"},
        )
    row_id, fmt, players, parsed_at = match_row
    game_rows = (
        await db.execute(
            text(
                """
                SELECT g.id, g.game_number, g.winner,
                       (SELECT MAX(s.turn_number)
                          FROM parser.game_states s
                         WHERE s.game_id = g.id) AS turns
                FROM parser.games g
                WHERE g.match_id = :match_id
                ORDER BY g.game_number
                """
            ),
            {"match_id": row_id},
        )
    ).all()
    games = [
        GameDetail(
            game_number=int(game_number),
            winner=winner,
            turns=int(turns) if turns is not None else None,
        )
        for (_game_id, game_number, winner, turns) in game_rows
    ]
    raw_players: list[Any] = list(players or [])
    return MatchDetail(
        match_id=str(row_id),
        format=fmt,
        players=[str(p) for p in raw_players],
        played_at=parsed_at,
        games=games,
    )
