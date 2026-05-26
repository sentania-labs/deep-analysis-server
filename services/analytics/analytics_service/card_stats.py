"""Per-card performance analytics endpoints.

v0.9.4: Original — LATERAL JSONB queries over game_states.

v0.9.6-F3/F4: Hero identification moved to parse time.

v0.9.6-F6/F7: Card stats are now queried from the materialized
``analytics.card_game_stats`` table, with fallback to the JSONB
extraction path for pre-backfill matches.  New endpoints: standout
cards, G1/G2/G3 split, opponent archetype and on_play filters.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user

router = APIRouter(prefix="/analytics/stats", tags=["card-stats"])


def _escape_like(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_DEFAULT_PER_PAGE = 20
_MAX_PER_PAGE = 100

# Minimum game count for top-performer standout card
TOP_PERFORMER_MIN_GAMES = 20

# Allowlist for card-stats sort_by — keep in sync with the dashboard
# Card Performance table headers.
_CARD_SORT_COLUMNS = frozenset({"card_name", "games", "win_rate", "avg_cast_turn"})
_CARD_SORT_DIRS = frozenset({"asc", "desc"})
# Natural direction for each sortable column. card_name is text → A→Z;
# numeric columns rank "best first" → descending.
_CARD_SORT_NATURAL_DIR = {
    "card_name": "asc",
    "games": "desc",
    "win_rate": "desc",
    "avg_cast_turn": "desc",
}


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CardStatItem(BaseModel):
    name: str
    cast_count: int = 0
    win_rate: float = 0.0
    avg_cast_turn: float | None = None
    type_line: str | None = None
    mana_cost: str | None = None


class CardStatsResponse(BaseModel):
    cards: list[CardStatItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = _DEFAULT_PER_PAGE


class FormatBreakdown(BaseModel):
    format: str
    total_games: int = 0
    wins: int = 0
    win_rate: float = 0.0


class GameNumberBreakdown(BaseModel):
    game_number: int
    total_games: int = 0
    wins: int = 0
    win_rate: float = 0.0
    cast_count: int = 0


class CardDetailResponse(BaseModel):
    name: str
    total_games: int = 0
    wins: int = 0
    win_rate: float = 0.0
    avg_cast_turn: float | None = None
    by_format: list[FormatBreakdown] = Field(default_factory=list)
    by_game_number: list[GameNumberBreakdown] = Field(default_factory=list)


class StandoutCard(BaseModel):
    name: str
    value: float = 0.0
    total_games: int = 0


class StandoutCardsResponse(BaseModel):
    top_performer: StandoutCard | None = None
    most_cast: StandoutCard | None = None
    most_seen: StandoutCard | None = None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _wr(wins: int, total: int) -> float:
    return (wins / total) * 100.0 if total else 0.0


async def _resolve_hero_name(
    db: AsyncSession,
    user_id: int,
) -> str | None:
    """Determine the hero name for SQL-level hero filtering.

    v0.9.6: Uses ``hero_player_name`` from the most recent match
    instead of querying ``auth.users``.
    """
    row = (
        await db.execute(
            text(
                """
                SELECT hero_player_name
                FROM parser.matches
                WHERE user_id = :user_id
                  AND hero_player_name IS NOT NULL
                  AND review_status IS NULL
                ORDER BY COALESCE(played_at, parsed_at) DESC
                LIMIT 1
                """
            ),
            {"user_id": user_id},
        )
    ).scalar_one_or_none()
    if row:
        return str(row)
    # Fallback: players[0] from any match
    fallback = (
        await db.execute(
            text(
                """
                SELECT players->>0
                FROM parser.matches
                WHERE user_id = :user_id
                  AND review_status IS NULL
                ORDER BY COALESCE(played_at, parsed_at) DESC
                LIMIT 1
                """
            ),
            {"user_id": user_id},
        )
    ).scalar_one_or_none()
    return str(fallback) if fallback else None


def _build_match_where(
    params: dict[str, Any],
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    opponent_archetype_id: str | None = None,
) -> str:
    """Build WHERE fragments that filter on parser.matches columns.

    Always emits a ``m.review_status IS NULL`` clause so holding-pen
    rows never feed into user-facing card stats.
    """
    clauses: list[str] = ["m.review_status IS NULL"]
    if format_filter:
        clauses.append("LOWER(m.format) = LOWER(:format)")
        params["format"] = format_filter
    if opponent:
        clauses.append("m.players::text ILIKE :opp_pattern ESCAPE '\\'")
        params["opp_pattern"] = f"%{_escape_like(opponent)}%"
    if date_from:
        clauses.append("COALESCE(m.played_at, m.parsed_at)::date >= :date_from")
        params["date_from"] = date_from
    if date_to:
        clauses.append("COALESCE(m.played_at, m.parsed_at)::date <= :date_to")
        params["date_to"] = date_to
    if opponent_archetype_id:
        clauses.append(
            "EXISTS (SELECT 1 FROM parser.match_archetypes opp_ma "
            "WHERE opp_ma.match_id = m.id "
            "AND opp_ma.player_name != COALESCE(m.hero_player_name, m.players->>0) "
            "AND opp_ma.archetype_id = :opp_arch_id)"
        )
        params["opp_arch_id"] = opponent_archetype_id
    return (" AND " + " AND ".join(clauses)) if clauses else ""


def _build_game_where(
    params: dict[str, Any],
    on_play: bool | None = None,
    is_postboard: bool | None = None,
) -> str:
    """Build WHERE fragments on card_game_stats / game_players columns."""
    clauses: list[str] = []
    if on_play is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM parser.game_players gp_filter "
            "WHERE gp_filter.game_id = cgs.game_id "
            "AND gp_filter.is_local = true AND gp_filter.on_play = :on_play)"
        )
        params["on_play"] = on_play
    if is_postboard is not None:
        clauses.append("cgs.is_postboard = :is_postboard")
        params["is_postboard"] = is_postboard
    return (" AND " + " AND ".join(clauses)) if clauses else ""


# ---------------------------------------------------------------------------
# Materialized table queries
# ---------------------------------------------------------------------------


async def _has_card_game_stats(db: AsyncSession, user_id: int) -> bool:
    """Check whether any card_game_stats rows exist for this user."""
    result = (
        await db.execute(
            text(
                "SELECT EXISTS("
                "  SELECT 1 FROM analytics.card_game_stats cgs"
                "  JOIN parser.matches m ON m.id = cgs.match_id"
                "  WHERE m.user_id = :user_id AND cgs.is_local = true"
                "    AND m.review_status IS NULL"
                "  LIMIT 1"
                ")"
            ),
            {"user_id": user_id},
        )
    ).scalar_one()
    return bool(result)


async def _card_stats_from_materialized(
    db: AsyncSession,
    user_id: int,
    *,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    opponent_archetype_id: str | None = None,
    on_play: bool | None = None,
    is_postboard: bool | None = None,
) -> list[dict[str, Any]]:
    """Aggregate card stats from the materialized card_game_stats table."""
    params: dict[str, Any] = {"user_id": user_id}
    match_where = _build_match_where(
        params,
        format_filter,
        opponent,
        date_from,
        date_to,
        opponent_archetype_id,
    )
    game_where = _build_game_where(params, on_play, is_postboard)

    card_filter = ""
    if card_name:
        card_filter = " AND LOWER(cgs.card_name) = LOWER(:card_name)"
        params["card_name"] = card_name

    sql = f"""
        SELECT cgs.card_name,
               COUNT(*) AS total_games,
               SUM(CASE WHEN cgs.won = true THEN 1 ELSE 0 END) AS wins,
               SUM(cgs.cast) AS total_cast,
               SUM(cgs.seen) AS total_seen,
               SUM(cgs.played) AS total_played,
               AVG(cgs.first_cast_turn) FILTER (
                   WHERE cgs.first_cast_turn IS NOT NULL
               ) AS avg_cast_turn
        FROM analytics.card_game_stats cgs
        JOIN parser.matches m ON m.id = cgs.match_id
        WHERE m.user_id = :user_id
          AND cgs.is_local = true
          {card_filter}
          {match_where}
          {game_where}
        GROUP BY cgs.card_name
    """
    rows = (await db.execute(text(sql), params)).all()
    return [
        {
            "card_name": str(r[0]),
            "total_games": int(r[1]),
            "wins": int(r[2]),
            "total_cast": int(r[3]),
            "total_seen": int(r[4]),
            "total_played": int(r[5]),
            "avg_cast_turn": float(r[6]) if r[6] is not None else None,
        }
        for r in rows
    ]


async def _card_detail_by_game_number(
    db: AsyncSession,
    user_id: int,
    card_name: str,
    *,
    format_filter: str | None = None,
    opponent_archetype_id: str | None = None,
    on_play: bool | None = None,
) -> list[GameNumberBreakdown]:
    """G1/G2/G3 breakdown from card_game_stats."""
    params: dict[str, Any] = {"user_id": user_id, "card_name": card_name}
    match_where = _build_match_where(
        params,
        format_filter,
        opponent_archetype_id=opponent_archetype_id,
    )
    game_where = _build_game_where(params, on_play)

    sql = f"""
        SELECT cgs.game_number,
               COUNT(*) AS total_games,
               SUM(CASE WHEN cgs.won = true THEN 1 ELSE 0 END) AS wins,
               SUM(cgs.cast) AS total_cast
        FROM analytics.card_game_stats cgs
        JOIN parser.matches m ON m.id = cgs.match_id
        WHERE m.user_id = :user_id
          AND cgs.is_local = true
          AND LOWER(cgs.card_name) = LOWER(:card_name)
          {match_where}
          {game_where}
        GROUP BY cgs.game_number
        ORDER BY cgs.game_number
    """
    rows = (await db.execute(text(sql), params)).all()
    return [
        GameNumberBreakdown(
            game_number=int(r[0]),
            total_games=int(r[1]),
            wins=int(r[2]),
            win_rate=_wr(int(r[2]), int(r[1])),
            cast_count=int(r[3]),
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Legacy JSONB fallback (for pre-backfill data)
# ---------------------------------------------------------------------------


async def _load_card_appearances(
    db: AsyncSession,
    user_id: int,
    hero_name: str | None,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[dict[str, Any]]:
    """Load per-game card appearance data using SQL-level JSONB extraction."""
    where = "WHERE m.user_id = :user_id AND m.review_status IS NULL"
    params: dict[str, Any] = {"user_id": user_id}
    if format_filter:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format_filter
    if opponent:
        where += " AND m.players::text ILIKE :opp_pattern ESCAPE '\\'"
        params["opp_pattern"] = f"%{_escape_like(opponent)}%"
    if date_from:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date >= :date_from"
        params["date_from"] = date_from
    if date_to:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date <= :date_to"
        params["date_to"] = date_to

    if not hero_name:
        return []

    hero_filter = "LOWER(player_entry.player_name) = LOWER(:hero_0)"
    params["hero_0"] = hero_name

    card_filter = ""
    if card_name:
        card_filter = " AND LOWER(card_elem.value->>'name') = LOWER(:card_name)"
        params["card_name"] = card_name

    sql = f"""
        SELECT g.id AS game_id,
               g.winner,
               m.players,
               m.format,
               card_elem.value->>'name' AS card_name,
               MIN(gs.turn_number) AS first_turn,
               COALESCE(m.hero_player_name, m.players->>0) AS hero
        FROM parser.game_states gs
        JOIN parser.games g ON g.id = gs.game_id
        JOIN parser.matches m ON m.id = g.match_id,
        LATERAL jsonb_each(gs.player_states) AS player_entry(player_name, player_data),
        LATERAL jsonb_array_elements(
            COALESCE(player_entry.player_data->'zones'->'battlefield', '[]'::jsonb)
        ) AS card_elem
        {where}
        AND ({hero_filter})
        AND card_elem.value->>'name' IS NOT NULL
        {card_filter}
        GROUP BY g.id, g.winner, m.players, m.format,
                 card_elem.value->>'name', m.hero_player_name
    """

    rows = (await db.execute(text(sql), params)).all()

    results: list[dict[str, Any]] = []
    for game_id, winner, players, fmt, cname, first_turn, hero in rows:
        results.append(
            {
                "game_id": game_id,
                "winner": winner,
                "players": list(players) if players else [],
                "format": fmt,
                "card_name": str(cname),
                "first_turn": int(first_turn),
                "hero": hero,
            }
        )
    return results


async def _load_card_appearances_fallback(
    db: AsyncSession,
    user_id: int,
    hero_name: str | None,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[dict[str, Any]]:
    """Fallback loader for battlefield entries stored as plain strings."""
    where = "WHERE m.user_id = :user_id AND m.review_status IS NULL"
    params: dict[str, Any] = {"user_id": user_id}
    if format_filter:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format_filter
    if opponent:
        where += " AND m.players::text ILIKE :opp_pattern ESCAPE '\\'"
        params["opp_pattern"] = f"%{_escape_like(opponent)}%"
    if date_from:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date >= :date_from"
        params["date_from"] = date_from
    if date_to:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date <= :date_to"
        params["date_to"] = date_to

    rows = (
        await db.execute(
            text(
                f"""
                SELECT g.id AS game_id, g.winner, m.players, m.format,
                       gs.turn_number, gs.player_states,
                       COALESCE(m.hero_player_name, m.players->>0) AS hero
                FROM parser.game_states gs
                JOIN parser.games g ON g.id = gs.game_id
                JOIN parser.matches m ON m.id = g.match_id
                {where}
                ORDER BY g.id, gs.turn_number
                """
            ),
            params,
        )
    ).all()

    game_cards: dict[Any, dict[str, int]] = {}
    game_meta: dict[Any, dict[str, Any]] = {}

    for game_id, winner, players, fmt, turn_number, player_states, hero in rows:
        if game_id not in game_meta:
            game_meta[game_id] = {
                "winner": winner,
                "players": list(players) if players else [],
                "format": fmt,
                "hero": hero,
            }

        if hero is None:
            continue

        states = player_states or {}
        hero_state = states.get(hero)
        if hero_state is None:
            for k, v in states.items():
                if k.lower() == hero.lower():
                    hero_state = v
                    break
        if hero_state is None:
            continue

        zones = hero_state.get("zones", {})
        battlefield = zones.get("battlefield", [])

        if game_id not in game_cards:
            game_cards[game_id] = {}

        for card in battlefield:
            cname = str(card) if not isinstance(card, dict) else card.get("name", str(card))
            if card_name and cname.lower() != card_name.lower():
                continue
            if cname not in game_cards[game_id]:
                game_cards[game_id][cname] = int(turn_number)

    results: list[dict[str, Any]] = []
    for gid, cards in game_cards.items():
        meta = game_meta[gid]
        for cname, first_turn in cards.items():
            results.append(
                {
                    "game_id": gid,
                    "winner": meta["winner"],
                    "players": meta["players"],
                    "format": meta["format"],
                    "card_name": cname,
                    "first_turn": first_turn,
                    "hero": meta.get("hero"),
                }
            )
    return results


async def _load_card_appearances_auto(
    db: AsyncSession,
    user_id: int,
    hero_name: str | None,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[dict[str, Any]]:
    """Try the fast SQL path first; fall back to Python extraction."""
    results = await _load_card_appearances(
        db,
        user_id,
        hero_name,
        card_name=card_name,
        format_filter=format_filter,
        opponent=opponent,
        date_from=date_from,
        date_to=date_to,
    )
    if results:
        return results

    where = "WHERE m.user_id = :user_id AND m.review_status IS NULL"
    params: dict[str, Any] = {"user_id": user_id}
    if format_filter:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format_filter

    has_data = (
        await db.execute(
            text(
                f"""
                SELECT EXISTS(
                    SELECT 1 FROM parser.game_states gs
                    JOIN parser.games g ON g.id = gs.game_id
                    JOIN parser.matches m ON m.id = g.match_id
                    {where}
                    LIMIT 1
                )
                """
            ),
            params,
        )
    ).scalar_one()

    if has_data:
        return await _load_card_appearances_fallback(
            db,
            user_id,
            hero_name,
            card_name=card_name,
            format_filter=format_filter,
            opponent=opponent,
            date_from=date_from,
            date_to=date_to,
        )
    return []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/cards", response_model=CardStatsResponse)
async def get_card_stats(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=_MAX_PER_PAGE)] = _DEFAULT_PER_PAGE,
    sort_by: Annotated[str, Query()] = "games",
    sort_dir: Annotated[str | None, Query()] = None,
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
    opponent_archetype_id: Annotated[uuid.UUID | None, Query()] = None,
    on_play: Annotated[bool | None, Query()] = None,
    is_postboard: Annotated[bool | None, Query()] = None,
) -> CardStatsResponse:
    """Per-card performance across all matches.

    Uses the materialized ``card_game_stats`` table when available,
    falling back to the legacy JSONB extraction path for pre-backfill
    data.

    ``sort_by`` accepts one of ``card_name``, ``games``, ``win_rate``,
    ``avg_cast_turn``. ``sort_dir`` is ``asc`` or ``desc``; if omitted,
    defaults to ``asc`` for ``card_name`` and ``desc`` for the numeric
    columns. Cards with ``avg_cast_turn = NULL`` always rank last when
    sorting by that column, regardless of direction.
    """
    if sort_by not in _CARD_SORT_COLUMNS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_sort_by", "allowed": sorted(_CARD_SORT_COLUMNS)},
        )
    if sort_dir is None:
        sort_dir = _CARD_SORT_NATURAL_DIR[sort_by]
    elif sort_dir not in _CARD_SORT_DIRS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_sort_dir", "allowed": sorted(_CARD_SORT_DIRS)},
        )

    use_materialized = await _has_card_game_stats(db, user.user_id)

    if use_materialized:
        agg_rows = await _card_stats_from_materialized(
            db,
            user.user_id,
            format_filter=format,
            opponent=opponent,
            date_from=date_from,
            date_to=date_to,
            opponent_archetype_id=str(opponent_archetype_id) if opponent_archetype_id else None,
            on_play=on_play,
            is_postboard=is_postboard,
        )
        # Fetch card metadata
        card_meta: dict[str, dict[str, str | None]] = {}
        if agg_rows:
            card_names = [r["card_name"] for r in agg_rows]
            meta_rows = (
                await db.execute(
                    text(
                        "SELECT name, type_line, mana_cost "
                        "FROM catalog.cards WHERE name = ANY(:names)"
                    ),
                    {"names": card_names},
                )
            ).all()
            for mname, type_line, mana_cost in meta_rows:
                card_meta[str(mname)] = {"type_line": type_line, "mana_cost": mana_cost}

        items: list[CardStatItem] = []
        for r in agg_rows:
            meta = card_meta.get(r["card_name"], {})
            avg_turn = r.get("avg_cast_turn")
            items.append(
                CardStatItem(
                    name=r["card_name"],
                    cast_count=r["total_cast"],
                    win_rate=_wr(r["wins"], r["total_games"]),
                    avg_cast_turn=round(avg_turn, 2) if avg_turn is not None else None,
                    type_line=meta.get("type_line"),
                    mana_cost=meta.get("mana_cost"),
                )
            )
    else:
        # Legacy path
        hero_name = await _resolve_hero_name(db, user.user_id)
        appearances = await _load_card_appearances_auto(
            db,
            user.user_id,
            hero_name,
            format_filter=format,
            opponent=opponent,
            date_from=date_from,
            date_to=date_to,
        )

        agg: dict[str, dict[str, Any]] = {}
        for a in appearances:
            cname = a["card_name"]
            hero = a.get("hero") or hero_name
            won = (
                a["winner"] is not None and hero is not None and a["winner"].lower() == hero.lower()
            )
            if cname not in agg:
                agg[cname] = {"count": 0, "wins": 0, "turn_sum": 0}
            agg[cname]["count"] += 1
            if won:
                agg[cname]["wins"] += 1
            agg[cname]["turn_sum"] += a["first_turn"]

        card_meta = {}
        if agg:
            card_names = list(agg.keys())
            meta_rows = (
                await db.execute(
                    text(
                        "SELECT name, type_line, mana_cost "
                        "FROM catalog.cards WHERE name = ANY(:names)"
                    ),
                    {"names": card_names},
                )
            ).all()
            for mname, type_line, mana_cost in meta_rows:
                card_meta[str(mname)] = {"type_line": type_line, "mana_cost": mana_cost}

        items = []
        for cname, data in agg.items():
            meta = card_meta.get(cname, {})
            avg_turn = data["turn_sum"] / data["count"] if data["count"] else None
            items.append(
                CardStatItem(
                    name=cname,
                    cast_count=data["count"],
                    win_rate=_wr(data["wins"], data["count"]),
                    avg_cast_turn=round(avg_turn, 2) if avg_turn is not None else None,
                    type_line=meta.get("type_line"),
                    mana_cost=meta.get("mana_cost"),
                )
            )

    _sort_card_items(items, sort_by, sort_dir)

    total = len(items)
    offset = (page - 1) * per_page
    page_items = items[offset : offset + per_page]

    return CardStatsResponse(cards=page_items, total=total, page=page, per_page=per_page)


def _sort_card_items(items: list[CardStatItem], sort_by: str, sort_dir: str) -> None:
    """Sort ``items`` in place by the chosen column and direction.

    Tie-break order is always ``cast_count`` desc then ``name`` asc, so
    equally-ranked cards prefer the larger sample size regardless of
    primary sort direction. ``avg_cast_turn = None`` rows always rank
    last when sorting by that column.
    """
    reverse = sort_dir == "desc"

    # Sort is stable, so apply the tie-breaker first then the primary
    # key. Items with equal primary values keep tie-breaker order.
    def tiebreak(x: CardStatItem) -> tuple[int, str]:
        return (-x.cast_count, x.name.lower())

    if sort_by == "avg_cast_turn":
        non_null = [x for x in items if x.avg_cast_turn is not None]
        nulls = [x for x in items if x.avg_cast_turn is None]
        non_null.sort(key=tiebreak)
        non_null.sort(key=lambda x: x.avg_cast_turn or 0.0, reverse=reverse)
        nulls.sort(key=tiebreak)
        items[:] = non_null + nulls
        return

    items.sort(key=tiebreak)
    if sort_by == "card_name":
        items.sort(key=lambda x: x.name.lower(), reverse=reverse)
    elif sort_by == "win_rate":
        items.sort(key=lambda x: x.win_rate, reverse=reverse)
    else:  # "games"
        items.sort(key=lambda x: x.cast_count, reverse=reverse)


@router.get("/cards/{card_name}", response_model=CardDetailResponse)
async def get_card_detail(
    card_name: str,
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    opponent_archetype_id: Annotated[uuid.UUID | None, Query()] = None,
    on_play: Annotated[bool | None, Query()] = None,
) -> CardDetailResponse:
    """Single card detail across all matches, with G1/G2/G3 breakdown."""
    use_materialized = await _has_card_game_stats(db, user.user_id)

    if use_materialized:
        agg_rows = await _card_stats_from_materialized(
            db,
            user.user_id,
            card_name=card_name,
            opponent_archetype_id=str(opponent_archetype_id) if opponent_archetype_id else None,
            on_play=on_play,
        )
        if not agg_rows:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "card_not_found"},
            )
        r = agg_rows[0]

        # Format breakdown
        params: dict[str, Any] = {"user_id": user.user_id, "card_name": card_name}
        match_where = _build_match_where(
            params,
            opponent_archetype_id=str(opponent_archetype_id) if opponent_archetype_id else None,
        )
        game_where = _build_game_where(params, on_play)
        fmt_rows = (
            await db.execute(
                text(
                    f"""
                    SELECT COALESCE(m.format, 'Unknown') AS fmt,
                           COUNT(*) AS total,
                           SUM(CASE WHEN cgs.won = true THEN 1 ELSE 0 END) AS wins
                    FROM analytics.card_game_stats cgs
                    JOIN parser.matches m ON m.id = cgs.match_id
                    WHERE m.user_id = :user_id
                      AND cgs.is_local = true
                      AND LOWER(cgs.card_name) = LOWER(:card_name)
                      {match_where}
                      {game_where}
                    GROUP BY COALESCE(m.format, 'Unknown')
                    ORDER BY COUNT(*) DESC
                    """
                ),
                params,
            )
        ).all()
        by_format = [
            FormatBreakdown(
                format=str(fr[0]),
                total_games=int(fr[1]),
                wins=int(fr[2]),
                win_rate=_wr(int(fr[2]), int(fr[1])),
            )
            for fr in fmt_rows
        ]

        # G1/G2/G3 breakdown
        by_game_number = await _card_detail_by_game_number(
            db,
            user.user_id,
            card_name,
            opponent_archetype_id=str(opponent_archetype_id) if opponent_archetype_id else None,
            on_play=on_play,
        )

        avg_turn = r.get("avg_cast_turn")
        return CardDetailResponse(
            name=card_name,
            total_games=r["total_games"],
            wins=r["wins"],
            win_rate=_wr(r["wins"], r["total_games"]),
            avg_cast_turn=round(avg_turn, 2) if avg_turn is not None else None,
            by_format=by_format,
            by_game_number=by_game_number,
        )

    # Legacy fallback
    hero_name = await _resolve_hero_name(db, user.user_id)
    appearances = await _load_card_appearances_auto(
        db,
        user.user_id,
        hero_name,
        card_name=card_name,
    )

    if not appearances:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "card_not_found"},
        )

    total = 0
    wins = 0
    turn_sum = 0
    by_format_dict: dict[str, dict[str, int]] = {}

    for a in appearances:
        hero = a.get("hero") or hero_name
        won = a["winner"] is not None and hero is not None and a["winner"].lower() == hero.lower()
        total += 1
        if won:
            wins += 1
        turn_sum += a["first_turn"]

        fmt = a["format"] or "Unknown"
        fb = by_format_dict.setdefault(fmt, {"total": 0, "wins": 0})
        fb["total"] += 1
        if won:
            fb["wins"] += 1

    avg_turn = turn_sum / total if total else None
    format_list = [
        FormatBreakdown(
            format=fmt,
            total_games=fb["total"],
            wins=fb["wins"],
            win_rate=_wr(fb["wins"], fb["total"]),
        )
        for fmt, fb in sorted(by_format_dict.items(), key=lambda kv: -kv[1]["total"])
    ]

    return CardDetailResponse(
        name=card_name,
        total_games=total,
        wins=wins,
        win_rate=_wr(wins, total),
        avg_cast_turn=round(avg_turn, 2) if avg_turn is not None else None,
        by_format=format_list,
        by_game_number=[],
    )


# ---------------------------------------------------------------------------
# Standout cards endpoint
# ---------------------------------------------------------------------------


@router.get("/standout-cards", response_model=StandoutCardsResponse)
async def get_standout_cards(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    opponent_archetype_id: Annotated[uuid.UUID | None, Query()] = None,
    on_play: Annotated[bool | None, Query()] = None,
    is_postboard: Annotated[bool | None, Query()] = None,
) -> StandoutCardsResponse:
    """Return standout cards: top performer (best win-rate-when-cast),
    most cast, and most seen.

    Requires materialized ``card_game_stats`` data. Returns empty
    standouts if no materialized data exists.
    """
    if not await _has_card_game_stats(db, user.user_id):
        return StandoutCardsResponse()

    params: dict[str, Any] = {"user_id": user.user_id}
    match_where = _build_match_where(
        params,
        format,
        opponent_archetype_id=str(opponent_archetype_id) if opponent_archetype_id else None,
    )
    game_where = _build_game_where(params, on_play, is_postboard)

    base_where = f"""
        FROM analytics.card_game_stats cgs
        JOIN parser.matches m ON m.id = cgs.match_id
        WHERE m.user_id = :user_id
          AND cgs.is_local = true
          {match_where}
          {game_where}
    """

    # Top performer: highest win rate when cast, min 20 games with cast > 0
    params_tp = {**params, "min_games": TOP_PERFORMER_MIN_GAMES}
    tp_row = (
        await db.execute(
            text(
                f"""
                SELECT cgs.card_name,
                       COUNT(*) AS total_games,
                       SUM(CASE WHEN cgs.won = true THEN 1 ELSE 0 END) AS wins
                {base_where}
                  AND cgs.cast > 0
                GROUP BY cgs.card_name
                HAVING COUNT(*) >= :min_games
                ORDER BY (SUM(CASE WHEN cgs.won = true THEN 1 ELSE 0 END)::float / COUNT(*)) DESC
                LIMIT 1
                """
            ),
            params_tp,
        )
    ).one_or_none()
    top_performer = None
    if tp_row:
        tp_name, tp_total, tp_wins = str(tp_row[0]), int(tp_row[1]), int(tp_row[2])
        top_performer = StandoutCard(
            name=tp_name,
            value=round(_wr(tp_wins, tp_total), 1),
            total_games=tp_total,
        )

    # Most cast
    mc_row = (
        await db.execute(
            text(
                f"""
                SELECT cgs.card_name,
                       SUM(cgs.cast) AS total_cast,
                       COUNT(*) AS total_games
                {base_where}
                GROUP BY cgs.card_name
                ORDER BY SUM(cgs.cast) DESC
                LIMIT 1
                """
            ),
            params,
        )
    ).one_or_none()
    most_cast = None
    if mc_row:
        most_cast = StandoutCard(
            name=str(mc_row[0]),
            value=float(mc_row[1]),
            total_games=int(mc_row[2]),
        )

    # Most seen
    ms_row = (
        await db.execute(
            text(
                f"""
                SELECT cgs.card_name,
                       SUM(cgs.seen) AS total_seen,
                       COUNT(*) AS total_games
                {base_where}
                GROUP BY cgs.card_name
                ORDER BY SUM(cgs.seen) DESC
                LIMIT 1
                """
            ),
            params,
        )
    ).one_or_none()
    most_seen = None
    if ms_row:
        most_seen = StandoutCard(
            name=str(ms_row[0]),
            value=float(ms_row[1]),
            total_games=int(ms_row[2]),
        )

    return StandoutCardsResponse(
        top_performer=top_performer,
        most_cast=most_cast,
        most_seen=most_seen,
    )


# ---------------------------------------------------------------------------
# Turn data endpoint
# ---------------------------------------------------------------------------


class TurnState(BaseModel):
    turn_number: int
    active_player: str | None = None
    players: dict[str, Any] = Field(default_factory=dict)
    stack: list[Any] = Field(default_factory=list)


@router.get(
    "/matches/{match_id}/games/{game_number}/turns",
    response_model=list[TurnState],
    tags=["turns"],
)
async def get_game_turns(
    match_id: uuid.UUID,
    game_number: int,
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[TurnState]:
    """Full game_states data for a single game within a match.

    Scoped to authenticated user (the match must belong to them).
    """
    # Verify match ownership; pending_review / rejected matches are
    # invisible to the user so the per-game turn view 404s for them too.
    match_row = (
        await db.execute(
            text(
                """
                SELECT id FROM parser.matches
                WHERE id = :match_id AND user_id = :user_id
                  AND review_status IS NULL
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

    # Find the game
    game_row = (
        await db.execute(
            text(
                """
                SELECT g.id FROM parser.games g
                WHERE g.match_id = :match_id AND g.game_number = :game_number
                """
            ),
            {"match_id": match_id, "game_number": game_number},
        )
    ).one_or_none()
    if game_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "game_not_found"},
        )

    game_id = game_row[0]

    # Load all game states for this game
    state_rows = (
        await db.execute(
            text(
                """
                SELECT gs.turn_number, gs.active_player, gs.player_states, gs.stack
                FROM parser.game_states gs
                WHERE gs.game_id = :game_id
                ORDER BY gs.turn_number
                """
            ),
            {"game_id": game_id},
        )
    ).all()

    return [
        TurnState(
            turn_number=int(turn_number),
            active_player=active_player,
            players=player_states or {},
            stack=list(stack) if stack else [],
        )
        for turn_number, active_player, player_states, stack in state_rows
    ]
