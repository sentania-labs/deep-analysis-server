"""Matchup analysis: hero archetype x opponent archetype matrix.

First slice of the "Matchup analysis dashboard" roadmap outcome (issue
#129). One read-only endpoint aggregates a user's matches into one cell per
(hero archetype, opponent archetype) pair, with the sample counts a caller
needs to avoid over-reading a thin cell.

Match scoping reuses :func:`analytics_service.stats._load_user_matches`, so
the format and date predicates, the ``review_status IS NULL`` exclusion and
the user scoping are the same ones ``/stats/by-opponent`` applies. Results
are classified with the same ``_classify_match`` and win rate uses the same
``wins / (wins + losses)`` convention. Archetypes come from
``parser.match_archetypes`` (one row per player per match) for both sides.

Matches missing either archetype are not in the matrix; their count is
returned as ``unclassified_matches`` so the gap is visible.

Each cell also carries a pre-board (game 1) vs post-board (games 2 and up)
split of game results, built from ``parser.games`` with the same hero rule
as the matrix. The cell's ``matches`` count and the split's ``games`` counts
are different units: a best-of-three match contributes one match and two or
three games.

``GET /stats/matchups/cards`` is the third slice: for one hero x opponent
archetype pair it returns the hero's per-card results (key cards) and a
sideboard effectiveness list (cards seen in games 2+ of a match but not in its
game 1). Cards come from ``analytics.card_game_stats`` (hero rows only), so a
match not yet materialized there contributes neither card rows nor games to
the sideboard baseline.
"""

from __future__ import annotations

import math
import uuid
from datetime import date
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user
from analytics_service.stats import (
    _classify_match,
    _get_redis_or_none,
    _load_user_matches,
)
from common.cache import cache_key, get_cached, set_cached

router = APIRouter(prefix="/analytics/stats", tags=["matchups"])

# A cell with fewer decided (won or lost) matches than this is flagged
# ``low_sample``: its win rate is shown but should not be acted on.
MATCHUP_MIN_SAMPLE = 5

# z for a 95% Wilson score interval.
_WILSON_Z = 1.96


class BoardSplit(BaseModel):
    """Game results for one side of the pre-board / post-board divide.

    Only games with a recorded winner count. ``games`` is therefore the
    denominator ``win_rate`` is computed over, and ``low_sample`` applies the
    same ``MATCHUP_MIN_SAMPLE`` threshold the cell does, to this split's own
    count.
    """

    games: int = 0
    wins: int = 0
    losses: int = 0
    win_rate: float = 0.0
    win_rate_low: float = 0.0
    win_rate_high: float = 0.0
    low_sample: bool = True


class MatchupCell(BaseModel):
    hero_archetype_id: uuid.UUID
    hero_archetype: str
    opponent_archetype_id: uuid.UUID
    opponent_archetype: str
    matches: int = 0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    # wins + losses: the denominator ``win_rate`` is computed over.
    decided: int = 0
    win_rate: float = 0.0
    # 95% Wilson score interval around ``win_rate`` (percent); both 0.0
    # when nothing was decided.
    win_rate_low: float = 0.0
    win_rate_high: float = 0.0
    low_sample: bool = True
    # Game 1 vs games 2+. A cell whose matches never went past game 1 has an
    # empty ``postboard`` (0 games, ``low_sample`` true), never a zero win rate
    # presented as a result.
    preboard: BoardSplit = Field(default_factory=BoardSplit)
    postboard: BoardSplit = Field(default_factory=BoardSplit)


class MatchupCard(BaseModel):
    """One hero card's results over the games of a matchup it appeared in.

    ``games`` counts games with a recorded winner in which the card was seen
    (cast, played or otherwise logged); ``matches`` the distinct matches those
    games belong to. ``cast_count`` totals casts across them.
    """

    card_name: str
    games: int = 0
    matches: int = 0
    wins: int = 0
    losses: int = 0
    win_rate: float = 0.0
    win_rate_low: float = 0.0
    win_rate_high: float = 0.0
    low_sample: bool = True
    cast_count: int = 0
    preboard: BoardSplit = Field(default_factory=BoardSplit)
    postboard: BoardSplit = Field(default_factory=BoardSplit)


class SideboardCard(BaseModel):
    """A card seen in games 2+ of a match whose game 1 it was not seen in.

    ``games`` / ``wins`` / ``losses`` / ``win_rate`` cover those post-board
    games. ``baseline_*`` cover the matchup's other decided post-board games,
    the ones the card was not seen in. ``delta`` is ``win_rate`` minus
    ``baseline_win_rate`` in percentage points, ``None`` when there is no
    baseline game. ``low_sample`` is true when either side has fewer than
    ``min_sample`` games.
    """

    card_name: str
    games: int = 0
    matches: int = 0
    wins: int = 0
    losses: int = 0
    win_rate: float = 0.0
    win_rate_low: float = 0.0
    win_rate_high: float = 0.0
    baseline_games: int = 0
    baseline_wins: int = 0
    baseline_win_rate: float = 0.0
    delta: float | None = None
    low_sample: bool = True


class MatchupCardsResponse(BaseModel):
    min_sample: int = MATCHUP_MIN_SAMPLE
    hero_archetype_id: uuid.UUID
    opponent_archetype_id: uuid.UUID
    # Matches in scope for this archetype pair (the matrix cell's match count).
    matches: int = 0
    cards: list[MatchupCard] = Field(default_factory=list)
    sideboard: list[SideboardCard] = Field(default_factory=list)


class MatchupMatrixResponse(BaseModel):
    min_sample: int = MATCHUP_MIN_SAMPLE
    cells: list[MatchupCell] = Field(default_factory=list)
    # Matches in the format/date scope with no hero or no opponent archetype.
    # Matches dropped by the archetype filters are not counted here.
    unclassified_matches: int = 0


def _wilson_interval(wins: int, decided: int) -> tuple[float, float]:
    """95% Wilson score interval for ``wins / decided``, as percentages."""
    if decided <= 0:
        return 0.0, 0.0
    p = wins / decided
    z2 = _WILSON_Z**2
    denom = 1 + z2 / decided
    centre = (p + z2 / (2 * decided)) / denom
    margin = (_WILSON_Z * math.sqrt(p * (1 - p) / decided + z2 / (4 * decided**2))) / denom
    return max(0.0, centre - margin) * 100.0, min(1.0, centre + margin) * 100.0


def _board_split(wins: int, losses: int) -> BoardSplit:
    low, high = _wilson_interval(wins, wins + losses)
    games = wins + losses
    return BoardSplit(
        games=games,
        wins=wins,
        losses=losses,
        win_rate=(wins / games) * 100.0 if games else 0.0,
        win_rate_low=low,
        win_rate_high=high,
        low_sample=games < MATCHUP_MIN_SAMPLE,
    )


async def _load_game_winners(
    db: AsyncSession,
    match_ids: list[Any],
) -> dict[Any, list[tuple[int, str]]]:
    """Map match id to ``(game_number, winner)`` for games with a winner."""
    rows = (
        await db.execute(
            text(
                """
                SELECT match_id, game_number, winner
                FROM parser.games
                WHERE match_id = ANY(:match_ids)
                  AND winner IS NOT NULL
                """
            ),
            {"match_ids": match_ids},
        )
    ).all()
    out: dict[Any, list[tuple[int, str]]] = {}
    for match_id, game_number, winner in rows:
        out.setdefault(match_id, []).append((int(game_number), str(winner)))
    return out


async def _load_match_archetypes(
    db: AsyncSession,
    match_ids: list[Any],
) -> dict[Any, tuple[tuple[uuid.UUID, str] | None, tuple[uuid.UUID, str] | None]]:
    """Map match id to ``(hero, opponent)`` ``(archetype_id, name)`` pairs.

    The hero is the row for ``COALESCE(hero_player_name, players[0])`` (the
    same hero rule ``card_stats`` uses for its opponent filter); the opponent
    is the other player's row. A side with no archetype is ``None``.
    """
    rows = (
        await db.execute(
            text(
                """
                SELECT m.id,
                       hero_ma.archetype_id AS hero_arch_id,
                       hero_a.name AS hero_arch_name,
                       opp_ma.archetype_id AS opp_arch_id,
                       opp_a.name AS opp_arch_name
                FROM parser.matches m
                LEFT JOIN parser.match_archetypes hero_ma
                       ON hero_ma.match_id = m.id
                      AND hero_ma.player_name = COALESCE(m.hero_player_name, m.players->>0)
                LEFT JOIN analytics.archetypes hero_a ON hero_a.id = hero_ma.archetype_id
                LEFT JOIN parser.match_archetypes opp_ma
                       ON opp_ma.match_id = m.id
                      AND opp_ma.player_name != COALESCE(m.hero_player_name, m.players->>0)
                LEFT JOIN analytics.archetypes opp_a ON opp_a.id = opp_ma.archetype_id
                WHERE m.id = ANY(:match_ids)
                """
            ),
            {"match_ids": match_ids},
        )
    ).all()
    out: dict[Any, tuple[tuple[uuid.UUID, str] | None, tuple[uuid.UUID, str] | None]] = {}
    for match_id, hero_id, hero_name, opp_id, opp_name in rows:
        hero = (hero_id, str(hero_name)) if hero_id and hero_name else None
        opp = (opp_id, str(opp_name)) if opp_id and opp_name else None
        out[match_id] = (hero, opp)
    return out


@router.get("/matchups", response_model=MatchupMatrixResponse)
async def get_matchups(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
    hero_archetype_id: Annotated[uuid.UUID | None, Query()] = None,
    opponent_archetype_id: Annotated[uuid.UUID | None, Query()] = None,
) -> MatchupMatrixResponse:
    """Hero archetype x opponent archetype win-rate matrix for the caller.

    Honours the same ``format`` / ``date_from`` / ``date_to`` filters as
    ``/stats/by-opponent`` (``format=all`` means no filter) and can be
    narrowed to one hero and/or one opponent archetype. Pending-review
    matches never contribute. Cells are ordered by match count, busiest
    first.
    """
    format_filter = format if format and format.lower() != "all" else None

    redis_client = await _get_redis_or_none()
    ck = cache_key(
        user.user_id,
        "matchups-split",
        format=format_filter.lower() if format_filter else None,
        date_from=date_from,
        date_to=date_to,
        hero_archetype_id=hero_archetype_id,
        opponent_archetype_id=opponent_archetype_id,
    )
    if redis_client:
        cached = await get_cached(redis_client, ck, endpoint="matchups-split")
        if isinstance(cached, dict):
            return MatchupMatrixResponse(**cached)

    matches = await _load_user_matches(
        db,
        user.user_id,
        date_from=date_from,
        date_to=date_to,
        format_=format_filter,
    )
    match_ids = [m["id"] for m in matches]
    archetypes = await _load_match_archetypes(db, match_ids) if matches else {}
    game_winners = await _load_game_winners(db, match_ids) if matches else {}

    buckets: dict[tuple[uuid.UUID, uuid.UUID], dict[str, Any]] = {}
    unclassified = 0
    for m in matches:
        hero, opp = archetypes.get(m["id"], (None, None))
        if hero is None or opp is None:
            unclassified += 1
            continue
        if hero_archetype_id and hero[0] != hero_archetype_id:
            continue
        if opponent_archetype_id and opp[0] != opponent_archetype_id:
            continue
        result_code, _opp_name, _pw, _pl = _classify_match(
            m["players"],
            m["wins_by_player"],
            m.get("hero_player_name"),
            match_tied=m.get("match_tied", False),
        )
        bucket = buckets.setdefault(
            (hero[0], opp[0]),
            {
                "hero_name": hero[1],
                "opp_name": opp[1],
                "matches": 0,
                "wins": 0,
                "losses": 0,
                "draws": 0,
                "pre_w": 0,
                "pre_l": 0,
                "post_w": 0,
                "post_l": 0,
            },
        )
        bucket["matches"] += 1
        hero_name = m.get("hero_player_name") or (m["players"][0] if m["players"] else None)
        for game_number, winner in game_winners.get(m["id"], []):
            if hero_name is None:
                break
            side = "pre" if game_number == 1 else "post"
            bucket[f"{side}_w" if winner.lower() == hero_name.lower() else f"{side}_l"] += 1
        if result_code == "W":
            bucket["wins"] += 1
        elif result_code == "L":
            bucket["losses"] += 1
        elif result_code == "D":
            bucket["draws"] += 1

    cells: list[MatchupCell] = []
    for (hero_id, opp_id), b in sorted(
        buckets.items(), key=lambda kv: (-kv[1]["matches"], kv[1]["hero_name"], kv[1]["opp_name"])
    ):
        decided = b["wins"] + b["losses"]
        low, high = _wilson_interval(b["wins"], decided)
        cells.append(
            MatchupCell(
                hero_archetype_id=hero_id,
                hero_archetype=b["hero_name"],
                opponent_archetype_id=opp_id,
                opponent_archetype=b["opp_name"],
                matches=b["matches"],
                wins=b["wins"],
                losses=b["losses"],
                draws=b["draws"],
                decided=decided,
                win_rate=(b["wins"] / decided) * 100.0 if decided else 0.0,
                win_rate_low=low,
                win_rate_high=high,
                low_sample=decided < MATCHUP_MIN_SAMPLE,
                preboard=_board_split(b["pre_w"], b["pre_l"]),
                postboard=_board_split(b["post_w"], b["post_l"]),
            )
        )
    out = MatchupMatrixResponse(cells=cells, unclassified_matches=unclassified)
    if redis_client:
        await set_cached(redis_client, ck, out.model_dump(mode="json"))
    return out


async def _load_hero_card_rows(
    db: AsyncSession,
    match_ids: list[Any],
) -> list[tuple[Any, int, str, bool | None, int]]:
    """Hero ``(match_id, game_number, card_name, won, cast)`` rows for the matches."""
    rows = (
        await db.execute(
            text(
                """
                SELECT match_id, game_number, card_name, won, "cast"
                FROM analytics.card_game_stats
                WHERE match_id = ANY(:match_ids)
                  AND is_local = true
                """
            ),
            {"match_ids": match_ids},
        )
    ).all()
    return [(r[0], int(r[1]), str(r[2]), r[3], int(r[4] or 0)) for r in rows]


def _rate(wins: int, games: int) -> float:
    return (wins / games) * 100.0 if games else 0.0


def _key_cards(rows: list[tuple[Any, int, str, bool | None, int]]) -> list[MatchupCard]:
    per_card: dict[str, dict[str, Any]] = {}
    for match_id, game_number, card, won, cast in rows:
        if won is None:
            continue
        b = per_card.setdefault(
            card,
            {"matches": set(), "cast": 0, "pre_w": 0, "pre_l": 0, "post_w": 0, "post_l": 0},
        )
        b["matches"].add(match_id)
        b["cast"] += cast
        side = "pre" if game_number == 1 else "post"
        b[f"{side}_w" if won else f"{side}_l"] += 1
    cards: list[MatchupCard] = []
    for card, b in per_card.items():
        wins = b["pre_w"] + b["post_w"]
        losses = b["pre_l"] + b["post_l"]
        games = wins + losses
        low, high = _wilson_interval(wins, games)
        cards.append(
            MatchupCard(
                card_name=card,
                games=games,
                matches=len(b["matches"]),
                wins=wins,
                losses=losses,
                win_rate=_rate(wins, games),
                win_rate_low=low,
                win_rate_high=high,
                low_sample=games < MATCHUP_MIN_SAMPLE,
                cast_count=b["cast"],
                preboard=_board_split(b["pre_w"], b["pre_l"]),
                postboard=_board_split(b["post_w"], b["post_l"]),
            )
        )
    cards.sort(key=lambda c: (-c.games, c.card_name.lower()))
    return cards


def _sideboard_cards(
    rows: list[tuple[Any, int, str, bool | None, int]],
    post_games: dict[tuple[Any, int], bool],
) -> list[SideboardCard]:
    """Cards seen post-board in a match whose game 1 they were not seen in.

    ``post_games`` maps ``(match_id, game_number)`` to whether the hero won,
    for every decided game 2 or later of the matchup; it is the pool the
    baseline is drawn from. A card's baseline is that pool minus every post-board
    game the card was seen in (sided in or not), so the two sides never overlap.
    """
    seen_g1: set[tuple[Any, str]] = {(m, c) for m, gn, c, _w, _cast in rows if gn == 1}
    seen_post: dict[str, set[tuple[Any, int]]] = {}
    sided: dict[str, dict[tuple[Any, int], bool]] = {}
    for match_id, game_number, card, won, _cast in rows:
        if game_number < 2 or won is None:
            continue
        key = (match_id, game_number)
        seen_post.setdefault(card, set()).add(key)
        if (match_id, card) not in seen_g1:
            sided.setdefault(card, {})[key] = bool(won)
    out: list[SideboardCard] = []
    for card, games_set in sided.items():
        wins = sum(1 for v in games_set.values() if v)
        games = len(games_set)
        baseline = [v for k, v in post_games.items() if k not in seen_post[card]]
        b_games = len(baseline)
        b_wins = sum(1 for v in baseline if v)
        low, high = _wilson_interval(wins, games)
        out.append(
            SideboardCard(
                card_name=card,
                games=games,
                matches=len({m for m, _gn in games_set}),
                wins=wins,
                losses=games - wins,
                win_rate=_rate(wins, games),
                win_rate_low=low,
                win_rate_high=high,
                baseline_games=b_games,
                baseline_wins=b_wins,
                baseline_win_rate=_rate(b_wins, b_games),
                delta=(_rate(wins, games) - _rate(b_wins, b_games)) if b_games else None,
                low_sample=games < MATCHUP_MIN_SAMPLE or b_games < MATCHUP_MIN_SAMPLE,
            )
        )
    out.sort(key=lambda c: (-c.games, c.card_name.lower()))
    return out


@router.get("/matchups/cards", response_model=MatchupCardsResponse)
async def get_matchup_cards(
    hero_archetype_id: Annotated[uuid.UUID, Query()],
    opponent_archetype_id: Annotated[uuid.UUID, Query()],
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
) -> MatchupCardsResponse:
    """Key cards and sideboard effectiveness for one hero x opponent pair.

    Matches are scoped exactly like ``/stats/matchups`` (caller's matches,
    ``format`` / ``date_from`` / ``date_to``, pending-review excluded) and
    narrowed to the archetype pair. ``cards`` lists the hero's cards by games
    seen; ``sideboard`` lists cards seen in games 2+ of a match but not in its
    game 1, with the win-rate delta against the matchup's other post-board
    games.
    """
    format_filter = format if format and format.lower() != "all" else None

    redis_client = await _get_redis_or_none()
    ck = cache_key(
        user.user_id,
        "matchup-cards",
        format=format_filter.lower() if format_filter else None,
        date_from=date_from,
        date_to=date_to,
        hero_archetype_id=hero_archetype_id,
        opponent_archetype_id=opponent_archetype_id,
    )
    if redis_client:
        cached = await get_cached(redis_client, ck, endpoint="matchup-cards")
        if isinstance(cached, dict):
            return MatchupCardsResponse(**cached)

    matches = await _load_user_matches(
        db,
        user.user_id,
        date_from=date_from,
        date_to=date_to,
        format_=format_filter,
    )
    archetypes = await _load_match_archetypes(db, [m["id"] for m in matches]) if matches else {}
    in_scope = []
    for m in matches:
        hero, opp = archetypes.get(m["id"], (None, None))
        if hero and opp and hero[0] == hero_archetype_id and opp[0] == opponent_archetype_id:
            in_scope.append(m)
    scope_ids = [m["id"] for m in in_scope]

    cards: list[MatchupCard] = []
    sideboard: list[SideboardCard] = []
    if scope_ids:
        rows = await _load_hero_card_rows(db, scope_ids)
        game_winners = await _load_game_winners(db, scope_ids)
        materialized = {r[0] for r in rows}
        post_games: dict[tuple[Any, int], bool] = {}
        for m in in_scope:
            if m["id"] not in materialized:
                continue
            hero_name = m.get("hero_player_name") or (m["players"][0] if m["players"] else None)
            if hero_name is None:
                continue
            for game_number, winner in game_winners.get(m["id"], []):
                if game_number >= 2:
                    post_games[(m["id"], game_number)] = winner.lower() == hero_name.lower()
        cards = _key_cards(rows)
        sideboard = _sideboard_cards(rows, post_games)

    out = MatchupCardsResponse(
        hero_archetype_id=hero_archetype_id,
        opponent_archetype_id=opponent_archetype_id,
        matches=len(in_scope),
        cards=cards,
        sideboard=sideboard,
    )
    if redis_client:
        await set_cached(redis_client, ck, out.model_dump(mode="json"))
    return out
