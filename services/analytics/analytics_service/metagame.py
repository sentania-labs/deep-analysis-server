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
from analytics_service.event_merger import (
    find_supplements_for,
    merge_events,
    merge_results,
)
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
    """Paginated recent events for a format, deduped across both feeds.

    The two scrapers run independently and frequently land the same
    real-world event in both tables (e.g. Pauper Leagues). We load
    everything for the format from each source and run the in-process
    :func:`analytics_service.event_merger.merge_events` matcher so the
    user sees one canonical row per logical event with mtgtop8 metadata
    winning when present. Pagination runs on the merged list.

    The format string is matched case-insensitively against the
    ``format`` column on both source tables.
    """
    fmt = format.title()
    params: dict[str, Any] = {"format": fmt}

    mtgtop8_rows = (
        await db.execute(
            text(
                "SELECT id, event_name, event_date, format, player_count "
                "FROM analytics.mtgtop8_events "
                "WHERE INITCAP(format) = :format"
            ),
            params,
        )
    ).all()
    mtgo_rows = (
        await db.execute(
            text(
                "SELECT id, event_name, event_date, format "
                "FROM analytics.mtgo_events "
                "WHERE INITCAP(format) = :format"
            ),
            params,
        )
    ).all()

    mtgtop8_events = [
        {
            "id": int(r[0]),
            "event_name": r[1],
            "event_date": r[2],
            "format": r[3],
            "player_count": int(r[4]) if r[4] is not None else None,
        }
        for r in mtgtop8_rows
    ]
    mtgo_events = [
        {
            "id": int(r[0]),
            "event_name": r[1],
            "event_date": r[2],
            "format": r[3],
            "player_count": None,
        }
        for r in mtgo_rows
    ]

    canonical = merge_events(mtgtop8_events, mtgo_events)
    total = len(canonical)

    offset = (page - 1) * per_page
    page_slice = canonical[offset : offset + per_page]
    events = [
        MetagameEvent(
            event_id=c.primary_event_id,
            event_name=c.event_name,
            event_date=c.event_date,
            player_count=c.player_count,
            source=c.primary_source,
            sources=list(c.sources),
        )
        for c in page_slice
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
    """Single event detail. Participants are unioned across feeds when
    the same logical event exists in both mtgtop8 and MTGO.

    The primary event (identified by *source* and *id*) provides the
    metadata. We then look up any matching event in the other source
    by the merger's match key (format + date + event-type signature)
    and union its participant rows into the result list. mtgtop8
    entries win on collisions so we don't drop the archetype labels.
    """
    if source not in _VALID_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"invalid source; allowed: {sorted(_VALID_SOURCES)}"},
        )

    fmt = format.title()
    primary_event = await _load_primary_event(db, source, id, fmt)
    if primary_event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "event_not_found"},
        )

    primary_results = await _load_results(db, source, id)

    # Find the sibling event in the OTHER source (only one direction —
    # an mtgtop8 event looks for an MTGO twin, an MTGO event looks for
    # an mtgtop8 twin). We use the same matcher as the listing so what
    # the user clicks through to mirrors what they saw in the list.
    other_source = "mtgo" if source == "mtgtop8" else "mtgtop8"
    other_candidates = await _load_candidate_events(db, other_source, fmt)
    siblings = find_supplements_for(
        primary_source=source,
        primary_event=primary_event,
        candidate_events=other_candidates,
    )

    sources_used = [source]
    supplement_rows: list[dict[str, Any]] = []
    for sibling in siblings:
        sib_results = await _load_results(db, other_source, int(sibling["id"]))
        supplement_rows.extend(sib_results)
    if siblings:
        sources_used.append(other_source)

    merged = merge_results(primary_results, supplement_rows)

    return EventDetail(
        event_id=int(primary_event["id"]),
        event_name=primary_event["event_name"],
        event_date=primary_event["event_date"],
        player_count=primary_event.get("player_count"),
        source=source,
        sources=sources_used,
        results=[
            EventResultEntry(
                player_name=r["player_name"],
                placement=r.get("placement"),
                deck_name=r.get("deck_name"),
                decklist_main=r.get("decklist_main") or {},
                decklist_sideboard=r.get("decklist_sideboard") or {},
            )
            for r in merged
        ],
    )


async def _load_primary_event(
    db: AsyncSession, source: str, event_id: int, fmt: str
) -> dict[str, Any] | None:
    if source == "mtgtop8":
        row = (
            await db.execute(
                text(
                    "SELECT id, event_name, event_date, format, player_count "
                    "FROM analytics.mtgtop8_events "
                    "WHERE id = :id AND INITCAP(format) = :format"
                ),
                {"id": event_id, "format": fmt},
            )
        ).one_or_none()
        if row is None:
            return None
        return {
            "id": int(row[0]),
            "event_name": row[1],
            "event_date": row[2],
            "format": row[3],
            "player_count": int(row[4]) if row[4] is not None else None,
        }
    row = (
        await db.execute(
            text(
                "SELECT id, event_name, event_date, format "
                "FROM analytics.mtgo_events "
                "WHERE id = :id AND INITCAP(format) = :format"
            ),
            {"id": event_id, "format": fmt},
        )
    ).one_or_none()
    if row is None:
        return None
    return {
        "id": int(row[0]),
        "event_name": row[1],
        "event_date": row[2],
        "format": row[3],
        "player_count": None,
    }


async def _load_candidate_events(db: AsyncSession, source: str, fmt: str) -> list[dict[str, Any]]:
    """Load all events for *source* filtered to *fmt*, for matcher lookups."""
    if source == "mtgtop8":
        rows = (
            await db.execute(
                text(
                    "SELECT id, event_name, event_date, format, player_count "
                    "FROM analytics.mtgtop8_events "
                    "WHERE INITCAP(format) = :format"
                ),
                {"format": fmt},
            )
        ).all()
        return [
            {
                "id": int(r[0]),
                "event_name": r[1],
                "event_date": r[2],
                "format": r[3],
                "player_count": int(r[4]) if r[4] is not None else None,
            }
            for r in rows
        ]
    rows = (
        await db.execute(
            text(
                "SELECT id, event_name, event_date, format "
                "FROM analytics.mtgo_events "
                "WHERE INITCAP(format) = :format"
            ),
            {"format": fmt},
        )
    ).all()
    return [
        {
            "id": int(r[0]),
            "event_name": r[1],
            "event_date": r[2],
            "format": r[3],
            "player_count": None,
        }
        for r in rows
    ]


async def _load_results(db: AsyncSession, source: str, event_id: int) -> list[dict[str, Any]]:
    if source == "mtgtop8":
        rows = (
            await db.execute(
                text(
                    "SELECT player_name, placement, deck_name, "
                    "decklist_main, decklist_sideboard "
                    "FROM analytics.mtgtop8_results "
                    "WHERE event_id = :event_id "
                    "ORDER BY placement NULLS LAST, player_name"
                ),
                {"event_id": event_id},
            )
        ).all()
        return [
            {
                "player_name": r[0],
                "placement": int(r[1]) if r[1] is not None else None,
                "deck_name": r[2],
                "decklist_main": r[3],
                "decklist_sideboard": r[4],
            }
            for r in rows
        ]
    rows = (
        await db.execute(
            text(
                "SELECT player_name, placement, "
                "decklist_main, decklist_sideboard "
                "FROM analytics.mtgo_results "
                "WHERE event_id = :event_id "
                "ORDER BY placement NULLS LAST, player_name"
            ),
            {"event_id": event_id},
        )
    ).all()
    return [
        {
            "player_name": r[0],
            "placement": int(r[1]) if r[1] is not None else None,
            "deck_name": None,
            "decklist_main": r[2],
            "decklist_sideboard": r[3],
        }
        for r in rows
    ]


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
