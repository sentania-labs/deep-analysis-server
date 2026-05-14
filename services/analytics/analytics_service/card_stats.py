"""Per-card performance analytics endpoints.

Queries ``parser.game_states.player_states`` JSONB to find cards that
appeared on the hero's battlefield, then aggregates win rate and cast-turn
data per card. Joins ``catalog.cards`` for metadata (type line, mana cost,
colors).

v0.9.4: Rewrote ``_load_card_appearances`` to push JSONB card extraction
to SQL using ``LATERAL jsonb_each`` / ``jsonb_array_elements``, eliminating
the Python loop over all game_states rows. At 2400 matches this reduces
the data transferred from ~216k JSONB rows to a focused per-game-per-card
result set.
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user

router = APIRouter(prefix="/analytics/stats", tags=["card-stats"])


_DEFAULT_PER_PAGE = 20
_MAX_PER_PAGE = 100


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


class CardDetailResponse(BaseModel):
    name: str
    total_games: int = 0
    wins: int = 0
    win_rate: float = 0.0
    avg_cast_turn: float | None = None
    by_format: list[FormatBreakdown] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


async def _load_mtgo_usernames(db: AsyncSession, user_id: int) -> list[str] | None:
    """Load MTGO usernames for the given user from auth schema."""
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


def _identify_hero(
    players: list[Any] | None,
    mtgo_usernames: list[str] | None,
) -> str | None:
    """Return the hero player name from the player list."""
    if not players:
        return None
    if mtgo_usernames:
        names_lower = {n.lower() for n in mtgo_usernames}
        for p in players:
            if str(p).lower() in names_lower:
                return str(p)
    return str(players[0])


def _resolve_hero_name(
    mtgo_usernames: list[str] | None,
    sample_players: list[Any] | None = None,
) -> str | None:
    """Determine the hero name for SQL-level hero filtering.

    Tries the first MTGO username; falls back to players[0] from
    a sample match if available.
    """
    if mtgo_usernames:
        return mtgo_usernames[0]
    if sample_players:
        return str(sample_players[0])
    return None


def _wr(wins: int, total: int) -> float:
    return (wins / total) * 100.0 if total else 0.0


async def _load_card_appearances(
    db: AsyncSession,
    user_id: int,
    mtgo_usernames: list[str] | None,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """Load per-game card appearance data using SQL-level JSONB extraction.

    v0.9.4: Pushes card extraction into SQL using LATERAL joins to
    avoid transferring all game_states JSONB to Python. For each game,
    extracts distinct card names on the hero's battlefield with their
    earliest turn number.
    """
    where = "WHERE m.user_id = :user_id"
    params: dict[str, Any] = {"user_id": user_id}
    if format_filter:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format_filter
    if opponent:
        where += " AND m.players @> :opp_json::jsonb"
        params["opp_json"] = json.dumps([opponent])
    if date_from:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date >= :date_from"
        params["date_from"] = date_from
    if date_to:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date <= :date_to"
        params["date_to"] = date_to

    # Determine hero names for SQL-level filtering across player_states keys
    hero_names: list[str] = []
    if mtgo_usernames:
        hero_names = list(mtgo_usernames)
    else:
        # Grab player[0] from the first match to use as hero fallback
        sample = (
            await db.execute(
                text(
                    f"""
                    SELECT m.players FROM parser.matches m
                    {where}
                    LIMIT 1
                    """
                ),
                params,
            )
        ).scalar_one_or_none()
        if sample and isinstance(sample, list) and sample:
            hero_names = [str(sample[0])]

    if not hero_names:
        return []

    # Build hero name matching for the LATERAL join.
    # We try exact match on each known hero name against the player_states keys.
    hero_conditions = []
    for i, hname in enumerate(hero_names):
        pkey = f"hero_{i}"
        hero_conditions.append(f"LOWER(player_entry.player_name) = LOWER(:{pkey})")
        params[pkey] = hname
    hero_filter = " OR ".join(hero_conditions)

    # Card name filter
    card_filter = ""
    if card_name:
        card_filter = " AND LOWER(card_elem.value->>'name') = LOWER(:card_name)"
        params["card_name"] = card_name

    # SQL-level JSONB extraction: for each game, find cards on the hero's
    # battlefield and their earliest turn of appearance.
    sql = f"""
        SELECT g.id AS game_id,
               g.winner,
               m.players,
               m.format,
               card_elem.value->>'name' AS card_name,
               MIN(gs.turn_number) AS first_turn
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
        GROUP BY g.id, g.winner, m.players, m.format, card_elem.value->>'name'
    """

    rows = (await db.execute(text(sql), params)).all()

    results: list[dict[str, Any]] = []
    for game_id, winner, players, fmt, cname, first_turn in rows:
        results.append(
            {
                "game_id": game_id,
                "winner": winner,
                "players": list(players) if players else [],
                "format": fmt,
                "card_name": str(cname),
                "first_turn": int(first_turn),
            }
        )
    return results


async def _load_card_appearances_fallback(
    db: AsyncSession,
    user_id: int,
    mtgo_usernames: list[str] | None,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """Fallback loader for battlefield entries stored as plain strings.

    When cards on the battlefield are stored as bare strings (not
    ``{name: ...}`` dicts), the SQL LATERAL approach using
    ``card_elem.value->>'name'`` won't match. This Python-side fallback
    handles that case.
    """
    where = "WHERE m.user_id = :user_id"
    params: dict[str, Any] = {"user_id": user_id}
    if format_filter:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format_filter
    if opponent:
        where += " AND m.players @> :opp_json::jsonb"
        params["opp_json"] = json.dumps([opponent])
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
                       gs.turn_number, gs.player_states
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

    for game_id, winner, players, fmt, turn_number, player_states in rows:
        if game_id not in game_meta:
            game_meta[game_id] = {
                "winner": winner,
                "players": list(players) if players else [],
                "format": fmt,
            }

        player_list = list(players) if players else []
        hero = _identify_hero(player_list, mtgo_usernames)
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
                }
            )
    return results


async def _load_card_appearances_auto(
    db: AsyncSession,
    user_id: int,
    mtgo_usernames: list[str] | None,
    card_name: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """Try the fast SQL path first; fall back to Python extraction if
    the SQL path returns no results but game_states exist (indicating
    string-format battlefield entries)."""
    results = await _load_card_appearances(
        db, user_id, mtgo_usernames,
        card_name=card_name,
        format_filter=format_filter,
        opponent=opponent,
        date_from=date_from,
        date_to=date_to,
    )
    if results:
        return results

    # Check if there are any game_states at all for this user
    where = "WHERE m.user_id = :user_id"
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
            db, user_id, mtgo_usernames,
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
    sort: Annotated[str, Query()] = "cast_count",
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    date_from: Annotated[str | None, Query()] = None,
    date_to: Annotated[str | None, Query()] = None,
) -> CardStatsResponse:
    """Per-card performance across all matches."""
    names = await _load_mtgo_usernames(db, user.user_id)
    appearances = await _load_card_appearances_auto(
        db,
        user.user_id,
        names,
        format_filter=format,
        opponent=opponent,
        date_from=date_from,
        date_to=date_to,
    )

    # Aggregate per card
    agg: dict[str, dict[str, Any]] = {}
    for a in appearances:
        cname = a["card_name"]
        hero = _identify_hero(a["players"], names)
        won = a["winner"] is not None and hero is not None and a["winner"].lower() == hero.lower()
        if cname not in agg:
            agg[cname] = {"count": 0, "wins": 0, "turn_sum": 0}
        agg[cname]["count"] += 1
        if won:
            agg[cname]["wins"] += 1
        agg[cname]["turn_sum"] += a["first_turn"]

    # Fetch card metadata for all card names
    card_meta: dict[str, dict[str, str | None]] = {}
    if agg:
        card_names = list(agg.keys())
        meta_rows = (
            await db.execute(
                text(
                    """
                    SELECT name, type_line, mana_cost
                    FROM catalog.cards
                    WHERE name = ANY(:names)
                    """
                ),
                {"names": card_names},
            )
        ).all()
        for mname, type_line, mana_cost in meta_rows:
            card_meta[str(mname)] = {"type_line": type_line, "mana_cost": mana_cost}

    # Build items
    items: list[CardStatItem] = []
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

    # Sort
    if sort == "win_rate":
        items.sort(key=lambda x: (-x.win_rate, -x.cast_count))
    else:
        items.sort(key=lambda x: (-x.cast_count, x.name))

    total = len(items)
    offset = (page - 1) * per_page
    page_items = items[offset : offset + per_page]

    return CardStatsResponse(cards=page_items, total=total, page=page, per_page=per_page)


@router.get("/cards/{card_name}", response_model=CardDetailResponse)
async def get_card_detail(
    card_name: str,
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> CardDetailResponse:
    """Single card detail across all matches."""
    names = await _load_mtgo_usernames(db, user.user_id)
    appearances = await _load_card_appearances_auto(db, user.user_id, names, card_name=card_name)

    if not appearances:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "card_not_found"},
        )

    total = 0
    wins = 0
    turn_sum = 0
    by_format: dict[str, dict[str, int]] = {}

    for a in appearances:
        hero = _identify_hero(a["players"], names)
        won = a["winner"] is not None and hero is not None and a["winner"].lower() == hero.lower()
        total += 1
        if won:
            wins += 1
        turn_sum += a["first_turn"]

        fmt = a["format"] or "Unknown"
        fb = by_format.setdefault(fmt, {"total": 0, "wins": 0})
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
        for fmt, fb in sorted(by_format.items(), key=lambda kv: -kv[1]["total"])
    ]

    return CardDetailResponse(
        name=card_name,
        total_games=total,
        wins=wins,
        win_rate=_wr(wins, total),
        avg_cast_turn=round(avg_turn, 2) if avg_turn is not None else None,
        by_format=format_list,
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
    # Verify match ownership
    match_row = (
        await db.execute(
            text(
                """
                SELECT id FROM parser.matches
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
