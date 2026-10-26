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
``parser.match_archetypes`` (one row per player per match), with the hero
side falling back to ``parser.matches.archetype_id``.

Matches missing either archetype are not in the matrix; their count is
returned as ``unclassified_matches`` so the gap is visible.

Follow-ups (not in this slice): game-number and pre/post-board split per
matchup, key cards scoped to a matchup, sideboard effectiveness.
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
                       COALESCE(hero_ma.archetype_id, m.archetype_id) AS hero_arch_id,
                       COALESCE(hero_a.name, m_a.name) AS hero_arch_name,
                       opp_ma.archetype_id AS opp_arch_id,
                       opp_a.name AS opp_arch_name
                FROM parser.matches m
                LEFT JOIN parser.match_archetypes hero_ma
                       ON hero_ma.match_id = m.id
                      AND hero_ma.player_name = COALESCE(m.hero_player_name, m.players->>0)
                LEFT JOIN analytics.archetypes hero_a ON hero_a.id = hero_ma.archetype_id
                LEFT JOIN analytics.archetypes m_a ON m_a.id = m.archetype_id
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
        "matchups",
        format=format_filter.lower() if format_filter else None,
        date_from=date_from,
        date_to=date_to,
        hero_archetype_id=hero_archetype_id,
        opponent_archetype_id=opponent_archetype_id,
    )
    if redis_client:
        cached = await get_cached(redis_client, ck, endpoint="matchups")
        if isinstance(cached, dict):
            return MatchupMatrixResponse(**cached)

    matches = await _load_user_matches(
        db,
        user.user_id,
        date_from=date_from,
        date_to=date_to,
        format_=format_filter,
    )
    archetypes = await _load_match_archetypes(db, [m["id"] for m in matches]) if matches else {}

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
            },
        )
        bucket["matches"] += 1
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
            )
        )
    out = MatchupMatrixResponse(cells=cells, unclassified_matches=unclassified)
    if redis_client:
        await set_cached(redis_client, ck, out.model_dump(mode="json"))
    return out
