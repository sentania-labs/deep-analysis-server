"""User-facing stats endpoints.

Reads ``parser.matches`` and ``parser.games`` cross-schema (analytics
holds no parser tables — see CLAUDE.md design decision #2). All endpoints
filter by ``user_id`` from the verified JWT and return empty data
gracefully when the user has no matches yet.

The "user perspective" within a match is currently inferred from
``match.players[0]`` — MTGO logs are uploaded by one of the two players
and the parser's player-ordering convention puts the uploader-side
account first. If the upstream parser ever changes that convention,
this module is the only consumer that needs to be updated.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user

router = APIRouter(prefix="/analytics/stats", tags=["stats"])


_RECENT_MATCH_LIMIT = 20


class RecentMatch(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    match_id: str
    played_at: datetime | None = None
    opponent: str | None = None
    result: str = ""
    format_: str | None = Field(default=None, alias="format")
    player_wins: int = 0
    player_losses: int = 0


class StatsSummary(BaseModel):
    total_matches: int = 0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    win_rate: float = 0.0
    recent_matches: list[RecentMatch] = Field(default_factory=list)


class FormatStat(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    format_: str = Field(alias="format")
    matches: int = 0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    win_rate: float = 0.0


class OpponentStat(BaseModel):
    opponent: str
    matches: int = 0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    win_rate: float = 0.0


def _classify_match(
    players: list[Any] | None,
    game_wins_by_player: dict[str, int],
) -> tuple[str, str | None, int, int]:
    """Return (result, opponent, player_wins, player_losses).

    - The "user" within the match is taken to be ``players[0]``.
    - W/L/D is derived from per-game wins, not the match-level
      ``winner`` column, so ties and unknowns produce the right shape.
    """
    if not players:
        return "", None, 0, 0
    user = str(players[0]) if players else None
    opponent = str(players[1]) if len(players) > 1 else None
    if user is None:
        return "", opponent, 0, 0
    user_wins = game_wins_by_player.get(user, 0)
    opp_wins = sum(v for k, v in game_wins_by_player.items() if k != user)
    if user_wins == 0 and opp_wins == 0:
        return "", opponent, 0, 0
    if user_wins > opp_wins:
        return "W", opponent, user_wins, opp_wins
    if user_wins < opp_wins:
        return "L", opponent, user_wins, opp_wins
    return "D", opponent, user_wins, opp_wins


async def _load_user_matches(db: AsyncSession, user_id: int) -> list[dict[str, Any]]:
    """Fetch a user's matches plus per-match game-winner counts."""
    rows = (
        await db.execute(
            text(
                """
                SELECT id, format, players, parsed_at
                FROM parser.matches
                WHERE user_id = :user_id
                ORDER BY parsed_at DESC
                """
            ),
            {"user_id": user_id},
        )
    ).all()
    if not rows:
        return []
    match_ids = [r[0] for r in rows]
    game_rows = (
        await db.execute(
            text(
                """
                SELECT match_id, winner, COUNT(*) AS n
                FROM parser.games
                WHERE match_id = ANY(:match_ids)
                  AND winner IS NOT NULL
                GROUP BY match_id, winner
                """
            ),
            {"match_ids": match_ids},
        )
    ).all()
    by_match: dict[Any, dict[str, int]] = {}
    for match_id, winner, n in game_rows:
        by_match.setdefault(match_id, {})[str(winner)] = int(n)
    out: list[dict[str, Any]] = []
    for match_id, fmt, players, parsed_at in rows:
        out.append(
            {
                "id": match_id,
                "format": fmt,
                "players": list(players or []),
                "parsed_at": parsed_at,
                "wins_by_player": by_match.get(match_id, {}),
            }
        )
    return out


def _summarize(matches: list[dict[str, Any]]) -> StatsSummary:
    if not matches:
        return StatsSummary()
    wins = losses = draws = 0
    recent: list[RecentMatch] = []
    for m in matches:
        result, opponent, pw, pl = _classify_match(m["players"], m["wins_by_player"])
        if result == "W":
            wins += 1
        elif result == "L":
            losses += 1
        elif result == "D":
            draws += 1
        if len(recent) < _RECENT_MATCH_LIMIT:
            recent.append(
                RecentMatch(
                    match_id=str(m["id"]),
                    played_at=m["parsed_at"],
                    opponent=opponent,
                    result=result,
                    format=m["format"],
                    player_wins=pw,
                    player_losses=pl,
                )
            )
    decided = wins + losses
    win_rate = (wins / decided) * 100.0 if decided else 0.0
    return StatsSummary(
        total_matches=len(matches),
        wins=wins,
        losses=losses,
        draws=draws,
        win_rate=win_rate,
        recent_matches=recent,
    )


@router.get("/summary", response_model=StatsSummary)
async def get_summary(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> StatsSummary:
    matches = await _load_user_matches(db, user.user_id)
    return _summarize(matches)


@router.get("/by-format", response_model=list[FormatStat])
async def get_by_format(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[FormatStat]:
    matches = await _load_user_matches(db, user.user_id)
    if not matches:
        return []
    buckets: dict[str, dict[str, int]] = {}
    for m in matches:
        fmt = m["format"] or "Unknown"
        bucket = buckets.setdefault(fmt, {"matches": 0, "wins": 0, "losses": 0, "draws": 0})
        bucket["matches"] += 1
        result, _opp, _pw, _pl = _classify_match(m["players"], m["wins_by_player"])
        if result == "W":
            bucket["wins"] += 1
        elif result == "L":
            bucket["losses"] += 1
        elif result == "D":
            bucket["draws"] += 1
    out: list[FormatStat] = []
    for fmt, b in sorted(buckets.items(), key=lambda kv: -kv[1]["matches"]):
        decided = b["wins"] + b["losses"]
        win_rate = (b["wins"] / decided) * 100.0 if decided else 0.0
        out.append(
            FormatStat(
                format=fmt,
                matches=b["matches"],
                wins=b["wins"],
                losses=b["losses"],
                draws=b["draws"],
                win_rate=win_rate,
            )
        )
    return out


@router.get("/by-opponent", response_model=list[OpponentStat])
async def get_by_opponent(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[OpponentStat]:
    matches = await _load_user_matches(db, user.user_id)
    if not matches:
        return []
    buckets: dict[str, dict[str, int]] = {}
    for m in matches:
        result, opponent, _pw, _pl = _classify_match(m["players"], m["wins_by_player"])
        if not opponent:
            continue
        bucket = buckets.setdefault(opponent, {"matches": 0, "wins": 0, "losses": 0, "draws": 0})
        bucket["matches"] += 1
        if result == "W":
            bucket["wins"] += 1
        elif result == "L":
            bucket["losses"] += 1
        elif result == "D":
            bucket["draws"] += 1
    out: list[OpponentStat] = []
    for opp, b in sorted(buckets.items(), key=lambda kv: -kv[1]["matches"]):
        decided = b["wins"] + b["losses"]
        win_rate = (b["wins"] / decided) * 100.0 if decided else 0.0
        out.append(
            OpponentStat(
                opponent=opp,
                matches=b["matches"],
                wins=b["wins"],
                losses=b["losses"],
                draws=b["draws"],
                win_rate=win_rate,
            )
        )
    return out
