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

from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
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
    mtgo_usernames: list[str] | None = None,
) -> tuple[str, str | None, int, int]:
    """Return (result, opponent, player_wins, player_losses).

    If ``mtgo_usernames`` is provided, the user is identified by
    matching against the player list. Falls back to ``players[0]``
    when no username matches.
    """
    if not players:
        return "", None, 0, 0
    user: str | None = None
    if mtgo_usernames:
        names_lower = {n.lower() for n in mtgo_usernames}
        for p in players:
            if str(p).lower() in names_lower:
                user = str(p)
                break
    if user is None:
        user = str(players[0])
    opponent = next((str(p) for p in players if str(p) != user), None)
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


async def _load_mtgo_usernames(db: AsyncSession, user_id: int) -> list[str] | None:
    try:
        row = (
            await db.execute(
                text("SELECT mtgo_usernames FROM auth.users WHERE id = :uid"),
                {"uid": user_id},
            )
        ).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        return None
    if row and isinstance(row, list):
        return row
    return None


async def _load_user_matches(db: AsyncSession, user_id: int) -> list[dict[str, Any]]:
    """Fetch a user's matches plus per-match game-winner counts."""
    rows = (
        await db.execute(
            text(
                """
                SELECT id, format, players,
                       COALESCE(played_at, parsed_at) AS played_at
                FROM parser.matches
                WHERE user_id = :user_id
                ORDER BY COALESCE(played_at, parsed_at) DESC
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
    for match_id, fmt, players, played_at in rows:
        out.append(
            {
                "id": match_id,
                "format": fmt,
                "players": list(players or []),
                "played_at": played_at,
                "wins_by_player": by_match.get(match_id, {}),
            }
        )
    return out


def _summarize(
    matches: list[dict[str, Any]],
    mtgo_usernames: list[str] | None = None,
) -> StatsSummary:
    if not matches:
        return StatsSummary()
    wins = losses = draws = 0
    recent: list[RecentMatch] = []
    for m in matches:
        result, opponent, pw, pl = _classify_match(
            m["players"],
            m["wins_by_player"],
            mtgo_usernames,
        )
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
                    played_at=m["played_at"],
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
    names = await _load_mtgo_usernames(db, user.user_id)
    return _summarize(matches, names)


@router.get("/by-format", response_model=list[FormatStat])
async def get_by_format(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[FormatStat]:
    matches = await _load_user_matches(db, user.user_id)
    if not matches:
        return []
    names = await _load_mtgo_usernames(db, user.user_id)
    buckets: dict[str, dict[str, int]] = {}
    for m in matches:
        fmt = m["format"] or "Unknown"
        bucket = buckets.setdefault(fmt, {"matches": 0, "wins": 0, "losses": 0, "draws": 0})
        bucket["matches"] += 1
        result, _opp, _pw, _pl = _classify_match(
            m["players"],
            m["wins_by_player"],
            names,
        )
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
    names = await _load_mtgo_usernames(db, user.user_id)
    buckets: dict[str, dict[str, int]] = {}
    for m in matches:
        result, opponent, _pw, _pl = _classify_match(
            m["players"],
            m["wins_by_player"],
            names,
        )
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


class UsernameSuggestion(BaseModel):
    username: str
    match_count: int


@router.get("/username-suggestion", response_model=list[UsernameSuggestion])
async def get_username_suggestion(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[UsernameSuggestion]:
    """Count player-name frequency across a user's matches and return
    the most common names as MTGO username suggestions."""
    rows = (
        await db.execute(
            text(
                """
                SELECT name, COUNT(*) AS n
                FROM parser.matches, jsonb_array_elements_text(players) AS name
                WHERE user_id = :user_id
                GROUP BY name
                ORDER BY n DESC
                LIMIT 5
                """
            ),
            {"user_id": user.user_id},
        )
    ).all()
    return [UsernameSuggestion(username=str(name), match_count=int(n)) for name, n in rows]


# ---------------------------------------------------------------------------
# Paginated match listing with filters
# ---------------------------------------------------------------------------

_MATCHES_DEFAULT_PER_PAGE = 20
_MATCHES_MAX_PER_PAGE = 100


class MatchListItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    match_id: str
    played_at: datetime | None = None
    opponent: str | None = None
    result: str = ""
    format_: str | None = Field(default=None, alias="format")
    player_wins: int = 0
    player_losses: int = 0


class MatchListResponse(BaseModel):
    matches: list[MatchListItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = _MATCHES_DEFAULT_PER_PAGE


@router.get("/matches", response_model=MatchListResponse)
async def list_matches(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=_MATCHES_MAX_PER_PAGE)] = _MATCHES_DEFAULT_PER_PAGE,
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    result: Annotated[str | None, Query()] = None,
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
) -> MatchListResponse:
    """Paginated, filterable match listing for the dashboard."""
    all_matches = await _load_user_matches(db, user.user_id)
    names = await _load_mtgo_usernames(db, user.user_id)

    # Classify all matches so we can filter by result / opponent
    classified: list[tuple[dict[str, Any], str, str | None, int, int]] = []
    for m in all_matches:
        r, opp, pw, pl = _classify_match(m["players"], m["wins_by_player"], names)
        classified.append((m, r, opp, pw, pl))

    # Apply filters
    if format and format.lower() != "all":
        classified = [
            (m, r, opp, pw, pl)
            for m, r, opp, pw, pl in classified
            if (m["format"] or "Unknown").lower() == format.lower()
        ]
    if opponent:
        needle = opponent.lower()
        classified = [
            (m, r, opp, pw, pl) for m, r, opp, pw, pl in classified if opp and needle in opp.lower()
        ]
    if result and result.lower() != "all":
        result_map = {"wins": "W", "losses": "L", "draws": "D"}
        target = result_map.get(result.lower(), result.upper())
        classified = [(m, r, opp, pw, pl) for m, r, opp, pw, pl in classified if r == target]
    if date_from:
        classified = [
            (m, r, opp, pw, pl)
            for m, r, opp, pw, pl in classified
            if m["played_at"] and m["played_at"].date() >= date_from
        ]
    if date_to:
        classified = [
            (m, r, opp, pw, pl)
            for m, r, opp, pw, pl in classified
            if m["played_at"] and m["played_at"].date() <= date_to
        ]

    total = len(classified)
    offset = (page - 1) * per_page
    page_items = classified[offset : offset + per_page]

    items = [
        MatchListItem(
            match_id=str(m["id"]),
            played_at=m["played_at"],
            opponent=opp,
            result=r,
            format=m["format"],
            player_wins=pw,
            player_losses=pl,
        )
        for m, r, opp, pw, pl in page_items
    ]
    return MatchListResponse(matches=items, total=total, page=page, per_page=per_page)
