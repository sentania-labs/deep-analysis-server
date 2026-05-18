"""Metagame API — public-facing archetype tiers, events, and trends.

Reads from ``analytics.mtgtop8_events``, ``analytics.mtgtop8_results``,
``analytics.mtgo_events``, and ``analytics.mtgo_results`` to present a
unified metagame view across scraped data sources.

All endpoints require authentication (``require_user``).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user
from analytics_service.schemas import (
    ArchetypeTier,
    EventDetail,
    EventResultEntry,
    MetagameEvent,
    MetagameEventList,
    MetagameFormat,
    MetagameFormatList,
    MetagameTierList,
    MetagameTrends,
    TrendDataset,
)

_log = logging.getLogger("analytics.metagame")

router = APIRouter(prefix="/analytics/metagame", tags=["metagame"])

_VALID_WINDOWS = {"14d", "30d", "90d", "all"}
_DEFAULT_WINDOW = "30d"
_DEFAULT_PER_PAGE = 20
_MAX_PER_PAGE = 100


def _window_cutoff(window: str) -> datetime | None:
    """Return a UTC cutoff datetime for the given window string, or None for 'all'."""
    if window == "all":
        return None
    days = {"14d": 14, "30d": 30, "90d": 90}[window]
    return datetime.now(UTC) - timedelta(days=days)


# ---------------------------------------------------------------------------
# GET /analytics/metagame/formats
# ---------------------------------------------------------------------------

_FORMATS_SQL = text("""
    SELECT format, event_count, latest_event_date
    FROM (
        SELECT
            COALESCE(INITCAP(e.format), 'Unknown') AS format,
            COUNT(*) AS event_count,
            MAX(e.event_date) AS latest_event_date
        FROM analytics.mtgtop8_events e
        WHERE e.format IS NOT NULL
        GROUP BY INITCAP(e.format)

        UNION ALL

        SELECT
            COALESCE(INITCAP(e.format), 'Unknown') AS format,
            COUNT(*) AS event_count,
            MAX(e.event_date) AS latest_event_date
        FROM analytics.mtgo_events e
        WHERE e.format IS NOT NULL
        GROUP BY INITCAP(e.format)
    ) sub
    GROUP BY format
    ORDER BY SUM(event_count) DESC
""")

# The outer GROUP BY merges the two UNION ALL halves per format.
# We re-aggregate so the caller sees one row per format.
_FORMATS_MERGED_SQL = text("""
    SELECT format, SUM(event_count)::int AS event_count,
           MAX(latest_event_date) AS latest_event_date
    FROM (
        SELECT
            COALESCE(INITCAP(e.format), 'Unknown') AS format,
            COUNT(*) AS event_count,
            MAX(e.event_date) AS latest_event_date
        FROM analytics.mtgtop8_events e
        WHERE e.format IS NOT NULL
        GROUP BY INITCAP(e.format)

        UNION ALL

        SELECT
            COALESCE(INITCAP(e.format), 'Unknown') AS format,
            COUNT(*) AS event_count,
            MAX(e.event_date) AS latest_event_date
        FROM analytics.mtgo_events e
        WHERE e.format IS NOT NULL
        GROUP BY INITCAP(e.format)
    ) sub
    GROUP BY format
    ORDER BY event_count DESC
""")


@router.get("/formats", response_model=MetagameFormatList)
async def list_formats(
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> MetagameFormatList:
    """List available formats with event counts from scraped data."""
    rows = (await db.execute(_FORMATS_MERGED_SQL)).all()
    formats = [
        MetagameFormat(
            format=row[0],
            event_count=int(row[1]),
            latest_event_date=row[2],
        )
        for row in rows
    ]
    return MetagameFormatList(formats=formats)


# ---------------------------------------------------------------------------
# GET /analytics/metagame/{format}/tiers
# ---------------------------------------------------------------------------


@router.get("/{format}/tiers", response_model=MetagameTierList)
async def format_tiers(
    format: str,
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    window: Annotated[str, Query()] = _DEFAULT_WINDOW,
) -> MetagameTierList:
    """Archetype tier list for a format, based on mtgtop8 results."""
    if window not in _VALID_WINDOWS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"invalid window; allowed: {sorted(_VALID_WINDOWS)}"},
        )
    cutoff = _window_cutoff(window)
    params: dict[str, Any] = {"format": format.title()}

    date_filter = ""
    if cutoff is not None:
        date_filter = "AND e.event_date >= :cutoff"
        params["cutoff"] = cutoff.date()

    # Query mtgtop8_results joined to events, grouped by deck_name.
    # MTGO results don't carry deck_name, so tiers are mtgtop8-only.
    tier_sql = text(f"""
        SELECT
            COALESCE(r.deck_name, 'Unknown') AS deck_name,
            COUNT(*) AS sample_count,
            AVG(r.placement)::float AS avg_placement
        FROM analytics.mtgtop8_results r
        JOIN analytics.mtgtop8_events e ON e.id = r.event_id
        WHERE INITCAP(e.format) = :format
        {date_filter}
        AND r.deck_name IS NOT NULL
        AND r.deck_name != ''
        GROUP BY COALESCE(r.deck_name, 'Unknown')
        ORDER BY sample_count DESC
    """)
    rows = (await db.execute(tier_sql, params)).all()

    total_results = sum(int(row[1]) for row in rows)
    tiers = [
        ArchetypeTier(
            deck_name=row[0],
            popularity_pct=round(int(row[1]) / total_results * 100, 2) if total_results else 0.0,
            avg_placement=round(float(row[2]), 2) if row[2] is not None else None,
            sample_count=int(row[1]),
        )
        for row in rows
    ]
    return MetagameTierList(
        format=format.title(),
        window=window,
        tiers=tiers,
        total_results=total_results,
    )


# ---------------------------------------------------------------------------
# GET /analytics/metagame/{format}/events
# ---------------------------------------------------------------------------


@router.get("/{format}/events", response_model=MetagameEventList)
async def format_events(
    format: str,
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=_MAX_PER_PAGE)] = _DEFAULT_PER_PAGE,
) -> MetagameEventList:
    """Paginated recent events for a format, combining both sources."""
    fmt = format.title()
    offset = (page - 1) * per_page
    params: dict[str, Any] = {"format": fmt, "limit": per_page, "offset": offset}

    # Count total across both sources.
    count_sql = text("""
        SELECT
            (SELECT COUNT(*) FROM analytics.mtgtop8_events
             WHERE INITCAP(format) = :format)
            +
            (SELECT COUNT(*) FROM analytics.mtgo_events
             WHERE INITCAP(format) = :format)
    """)
    total = int((await db.execute(count_sql, params)).scalar_one())

    # UNION ALL both sources, paginated.
    events_sql = text("""
        SELECT event_id, event_name, event_date, player_count, source
        FROM (
            SELECT id AS event_id, event_name, event_date, player_count,
                   'mtgtop8' AS source
            FROM analytics.mtgtop8_events
            WHERE INITCAP(format) = :format

            UNION ALL

            SELECT id AS event_id, event_name, event_date, NULL AS player_count,
                   'mtgo' AS source
            FROM analytics.mtgo_events
            WHERE INITCAP(format) = :format
        ) combined
        ORDER BY event_date DESC NULLS LAST, event_name
        LIMIT :limit OFFSET :offset
    """)
    rows = (await db.execute(events_sql, params)).all()
    events = [
        MetagameEvent(
            event_id=int(row[0]),
            event_name=row[1],
            event_date=row[2],
            player_count=int(row[3]) if row[3] is not None else None,
            source=row[4],
        )
        for row in rows
    ]
    return MetagameEventList(events=events, total=total, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# GET /analytics/metagame/{format}/events/{source}/{id}
# ---------------------------------------------------------------------------

_VALID_SOURCES = {"mtgtop8", "mtgo"}


@router.get("/{format}/events/{source}/{id}", response_model=EventDetail)
async def event_detail(
    format: str,
    source: str,
    id: int,
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> EventDetail:
    """Single event detail with all results."""
    if source not in _VALID_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"invalid source; allowed: {sorted(_VALID_SOURCES)}"},
        )
    if source == "mtgtop8":
        event_row = (
            await db.execute(
                text("""
                    SELECT id, event_name, event_date, player_count
                    FROM analytics.mtgtop8_events
                    WHERE id = :id AND INITCAP(format) = :format
                """),
                {"id": id, "format": format.title()},
            )
        ).one_or_none()
        if event_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "event_not_found"},
            )
        result_rows = (
            await db.execute(
                text("""
                    SELECT player_name, placement, deck_name,
                           decklist_main, decklist_sideboard
                    FROM analytics.mtgtop8_results
                    WHERE event_id = :event_id
                    ORDER BY placement NULLS LAST, player_name
                """),
                {"event_id": id},
            )
        ).all()
        return EventDetail(
            event_id=int(event_row[0]),
            event_name=event_row[1],
            event_date=event_row[2],
            player_count=int(event_row[3]) if event_row[3] is not None else None,
            source="mtgtop8",
            results=[
                EventResultEntry(
                    player_name=r[0],
                    placement=int(r[1]) if r[1] is not None else None,
                    deck_name=r[2],
                    decklist_main=r[3],
                    decklist_sideboard=r[4],
                )
                for r in result_rows
            ],
        )
    else:
        # mtgo source
        event_row = (
            await db.execute(
                text("""
                    SELECT id, event_name, event_date
                    FROM analytics.mtgo_events
                    WHERE id = :id AND INITCAP(format) = :format
                """),
                {"id": id, "format": format.title()},
            )
        ).one_or_none()
        if event_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "event_not_found"},
            )
        result_rows = (
            await db.execute(
                text("""
                    SELECT player_name, placement, NULL AS deck_name,
                           decklist_main, decklist_sideboard
                    FROM analytics.mtgo_results
                    WHERE event_id = :event_id
                    ORDER BY placement NULLS LAST, player_name
                """),
                {"event_id": id},
            )
        ).all()
        return EventDetail(
            event_id=int(event_row[0]),
            event_name=event_row[1],
            event_date=event_row[2],
            player_count=None,
            source="mtgo",
            results=[
                EventResultEntry(
                    player_name=r[0],
                    placement=int(r[1]) if r[1] is not None else None,
                    deck_name=r[2],
                    decklist_main=r[3],
                    decklist_sideboard=r[4],
                )
                for r in result_rows
            ],
        )


# ---------------------------------------------------------------------------
# GET /analytics/metagame/{format}/trends
# ---------------------------------------------------------------------------


@router.get("/{format}/trends", response_model=MetagameTrends)
async def format_trends(
    format: str,
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    window: Annotated[str, Query()] = _DEFAULT_WINDOW,
) -> MetagameTrends:
    """Historical archetype popularity grouped by ISO week."""
    if window not in _VALID_WINDOWS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"invalid window; allowed: {sorted(_VALID_WINDOWS)}"},
        )
    cutoff = _window_cutoff(window)
    params: dict[str, Any] = {"format": format.title()}

    date_filter = ""
    if cutoff is not None:
        date_filter = "AND e.event_date >= :cutoff"
        params["cutoff"] = cutoff.date()

    # Group by ISO year-week and deck_name.
    trends_sql = text(f"""
        SELECT
            TO_CHAR(e.event_date, 'IYYY-"W"IW') AS week_label,
            COALESCE(r.deck_name, 'Unknown') AS deck_name,
            COUNT(*) AS cnt
        FROM analytics.mtgtop8_results r
        JOIN analytics.mtgtop8_events e ON e.id = r.event_id
        WHERE INITCAP(e.format) = :format
        {date_filter}
        AND e.event_date IS NOT NULL
        AND r.deck_name IS NOT NULL
        AND r.deck_name != ''
        GROUP BY week_label, deck_name
        ORDER BY week_label
    """)
    rows = (await db.execute(trends_sql, params)).all()

    if not rows:
        return MetagameTrends(format=format.title(), window=window)

    # Build ordered set of week labels and deck names.
    week_set: dict[str, int] = {}
    deck_set: dict[str, dict[str, float]] = {}
    for week_label, deck_name, cnt in rows:
        if week_label not in week_set:
            week_set[week_label] = len(week_set)
        if deck_name not in deck_set:
            deck_set[deck_name] = {}
        deck_set[deck_name][week_label] = float(cnt)

    labels = list(week_set.keys())

    # Sort decks by total count descending, limit to top 10 for readability.
    sorted_decks = sorted(
        deck_set.items(),
        key=lambda kv: sum(kv[1].values()),
        reverse=True,
    )[:10]

    datasets = [
        TrendDataset(
            label=deck_name,
            data=[week_counts.get(w, 0.0) for w in labels],
        )
        for deck_name, week_counts in sorted_decks
    ]
    return MetagameTrends(
        format=format.title(),
        window=window,
        labels=labels,
        datasets=datasets,
    )
