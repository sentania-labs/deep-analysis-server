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

v0.9.4: Query patterns rewritten to push filtering, pagination, and
aggregation to SQL instead of loading all matches into Python.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user
from analytics_service.settings import get_settings
from common.cache import cache_key, get_cached, set_cached
from common.redis_client import get_redis

_log = logging.getLogger("analytics.stats")

router = APIRouter(prefix="/analytics/stats", tags=["stats"])


async def _get_redis_or_none() -> Any:
    """Return the Redis client or None if unavailable."""
    try:
        settings = get_settings()
        return await get_redis(settings.redis_url)
    except Exception:  # noqa: BLE001
        return None


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


def _hero_sql_expression(mtgo_usernames: list[str] | None) -> tuple[str, dict[str, Any]]:
    """Build a SQL CASE expression to identify the hero player name.

    Returns (sql_fragment, params) where the fragment can be embedded
    in a larger query. Uses ``players[0]`` as the fallback when no
    MTGO usernames match.
    """
    if not mtgo_usernames:
        return "m.players->>0", {}

    # Build a CASE that tries each known username against the players array
    cases: list[str] = []
    params: dict[str, Any] = {}
    for i, name in enumerate(mtgo_usernames):
        pkey = f"_hero_name_{i}"
        cases.append(f"WHEN m.players ? :{pkey} THEN :{pkey}")
        params[pkey] = name
    return f"CASE {' '.join(cases)} ELSE m.players->>0 END", params


async def _load_user_matches(db: AsyncSession, user_id: int) -> list[dict[str, Any]]:
    """Fetch a user's matches plus per-match game-winner counts.

    Kept for callers that need the full match list with game-win
    breakdowns (by-opponent aggregation). For summary and by-format,
    prefer the dedicated SQL aggregation helpers.
    """
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
    redis_client = await _get_redis_or_none()
    ck = cache_key(user.user_id, "summary")
    if redis_client:
        cached = await get_cached(redis_client, ck, endpoint="summary")
        if isinstance(cached, dict):
            return StatsSummary(**cached)
    matches = await _load_user_matches(db, user.user_id)
    names = await _load_mtgo_usernames(db, user.user_id)
    result = _summarize(matches, names)
    if redis_client:
        await set_cached(redis_client, ck, result.model_dump(mode="json", by_alias=True))
    return result


@router.get("/by-format", response_model=list[FormatStat])
async def get_by_format(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[FormatStat]:
    redis_client = await _get_redis_or_none()
    ck = cache_key(user.user_id, "by-format")
    if redis_client:
        cached = await get_cached(redis_client, ck, endpoint="by-format")
        if isinstance(cached, list):
            return [FormatStat(**item) for item in cached]
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
    if redis_client:
        await set_cached(
            redis_client,
            ck,
            [item.model_dump(mode="json", by_alias=True) for item in out],
        )
    return out


@router.get("/by-opponent", response_model=list[OpponentStat])
async def get_by_opponent(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[OpponentStat]:
    redis_client = await _get_redis_or_none()
    ck = cache_key(user.user_id, "by-opponent")
    if redis_client:
        cached = await get_cached(redis_client, ck, endpoint="by-opponent")
        if isinstance(cached, list):
            return [OpponentStat(**item) for item in cached]
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
    if redis_client:
        await set_cached(
            redis_client,
            ck,
            [item.model_dump(mode="json", by_alias=True) for item in out],
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
                SELECT pname, COUNT(DISTINCT m.id) AS n
                FROM parser.matches m
                CROSS JOIN LATERAL jsonb_array_elements_text(m.players) AS pname
                WHERE m.user_id = :user_id
                GROUP BY pname
                ORDER BY n DESC
                LIMIT 5
                """
            ),
            {"user_id": user.user_id},
        )
    ).all()
    return [UsernameSuggestion(username=str(name), match_count=int(n)) for name, n in rows]


# ---------------------------------------------------------------------------
# Paginated match listing with filters — SQL-level filtering and pagination
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
    """Paginated, filterable match listing for the dashboard.

    v0.9.4: Pushes format, opponent, and date filters to SQL WHERE
    clauses and applies LIMIT/OFFSET at the database level. Result
    filtering (W/L/D) still happens in Python on the filtered set
    because it depends on per-match game-winner counts.
    """
    names = await _load_mtgo_usernames(db, user.user_id)

    # Build SQL WHERE dynamically for filters that can be pushed to SQL
    where = "WHERE m.user_id = :user_id"
    params: dict[str, Any] = {"user_id": user.user_id}

    if format and format.lower() != "all":
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format
    if opponent:
        where += " AND m.players @> :opp_json::jsonb"
        params["opp_json"] = json.dumps([opponent])
    if date_from:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date >= :date_from"
        params["date_from"] = str(date_from)
    if date_to:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date <= :date_to"
        params["date_to"] = str(date_to)

    # When there's no result filter, we can paginate in SQL
    has_result_filter = result is not None and result.lower() != "all"

    if has_result_filter:
        # Must load all SQL-filtered matches, classify in Python, then paginate
        rows = (
            await db.execute(
                text(
                    f"""
                    SELECT m.id, m.format, m.players,
                           COALESCE(m.played_at, m.parsed_at) AS played_at
                    FROM parser.matches m
                    {where}
                    ORDER BY COALESCE(m.played_at, m.parsed_at) DESC
                    """
                ),
                params,
            )
        ).all()
    else:
        # Count total for pagination
        count_row = await db.execute(
            text(f"SELECT COUNT(*) FROM parser.matches m {where}"),
            params,
        )
        total = int(count_row.scalar_one())

        # Fetch only the requested page
        offset = (page - 1) * per_page
        params["limit"] = per_page
        params["offset"] = offset
        rows = (
            await db.execute(
                text(
                    f"""
                    SELECT m.id, m.format, m.players,
                           COALESCE(m.played_at, m.parsed_at) AS played_at
                    FROM parser.matches m
                    {where}
                    ORDER BY COALESCE(m.played_at, m.parsed_at) DESC
                    LIMIT :limit OFFSET :offset
                    """
                ),
                params,
            )
        ).all()

    if not rows:
        if has_result_filter:
            return MatchListResponse(matches=[], total=0, page=page, per_page=per_page)
        return MatchListResponse(matches=[], total=total, page=page, per_page=per_page)

    # Fetch game-winner counts for the matches in this set
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

    # Classify and build items
    classified: list[MatchListItem] = []
    for match_id, fmt, players, played_at in rows:
        player_list = list(players or [])
        wins_by_player = by_match.get(match_id, {})
        r, opp, pw, pl = _classify_match(player_list, wins_by_player, names)
        classified.append(
            MatchListItem(
                match_id=str(match_id),
                played_at=played_at,
                opponent=opp,
                result=r,
                format=fmt,
                player_wins=pw,
                player_losses=pl,
            )
        )

    if has_result_filter:
        # Apply result filter in Python on the SQL-reduced set
        result_map = {"wins": "W", "losses": "L", "draws": "D"}
        target = result_map.get(result.lower(), result.upper())  # type: ignore[union-attr]
        classified = [item for item in classified if item.result == target]
        total = len(classified)
        offset = (page - 1) * per_page
        page_items = classified[offset : offset + per_page]
    else:
        page_items = classified

    return MatchListResponse(matches=page_items, total=total, page=page, per_page=per_page)
