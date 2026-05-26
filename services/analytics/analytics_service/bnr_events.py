"""Banned & Restricted events router.

Admin CRUD on the ``analytics.bnr_events`` table plus a wiki-import
endpoint that fetches the MTG Fandom timeline page and parses B&R
announcements into events.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, date, datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_admin, require_user
from analytics_service.models import BnrEvent
from analytics_service.schemas import (
    BnrEventListView,
    BnrEventRecord,
    BnrEventWriteRequest,
    WikiImportResult,
)

_log = logging.getLogger("analytics.bnr_events")

router = APIRouter(prefix="/analytics/bnr-events", tags=["bnr-events"])


def _record(row: BnrEvent) -> BnrEventRecord:
    return BnrEventRecord(
        id=row.id,
        format=row.format,
        effective_date=row.effective_date,
        description=row.description,
        card_actions=list(row.card_actions or []),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("", response_model=BnrEventListView)
async def list_bnr_events(
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> BnrEventListView:
    rows = (
        (await db.execute(select(BnrEvent).order_by(BnrEvent.effective_date.desc())))
        .scalars()
        .all()
    )
    total = int((await db.execute(select(func.count()).select_from(BnrEvent))).scalar_one())
    return BnrEventListView(events=[_record(r) for r in rows], total=total)


@router.get("/by-format", response_model=BnrEventListView)
async def list_bnr_events_by_format(
    format: str,
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> BnrEventListView:
    rows = (
        (
            await db.execute(
                select(BnrEvent)
                .where(func.lower(BnrEvent.format) == format.lower())
                .order_by(BnrEvent.effective_date.desc())
            )
        )
        .scalars()
        .all()
    )
    total = len(rows)
    return BnrEventListView(events=[_record(r) for r in rows], total=total)


@router.post(
    "",
    response_model=BnrEventRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_bnr_event(
    body: BnrEventWriteRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> BnrEventRecord:
    row = BnrEvent(
        id=uuid.uuid4(),
        format=body.format,
        effective_date=body.effective_date,
        description=body.description,
        card_actions=[ca.model_dump() for ca in body.card_actions],
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _record(row)


@router.get("/{event_id}", response_model=BnrEventRecord)
async def get_bnr_event(
    event_id: uuid.UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> BnrEventRecord:
    row = (await db.execute(select(BnrEvent).where(BnrEvent.id == event_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "bnr_event_not_found"},
        )
    return _record(row)


@router.put("/{event_id}", response_model=BnrEventRecord)
async def update_bnr_event(
    event_id: uuid.UUID,
    body: BnrEventWriteRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> BnrEventRecord:
    row = (await db.execute(select(BnrEvent).where(BnrEvent.id == event_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "bnr_event_not_found"},
        )
    row.format = body.format
    row.effective_date = body.effective_date
    row.description = body.description
    row.card_actions = [ca.model_dump() for ca in body.card_actions]
    row.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(row)
    return _record(row)


@router.delete("/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_bnr_event(
    event_id: uuid.UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> Response:
    result = await db.execute(delete(BnrEvent).where(BnrEvent.id == event_id))
    await db.commit()
    rowcount: int = result.rowcount  # type: ignore[attr-defined]
    if rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "bnr_event_not_found"},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Wiki import
# ---------------------------------------------------------------------------

_WIKI_API_URL = (
    "https://mtg.fandom.com/api.php"
    "?action=parse&page=Banned_and_restricted_cards/Timeline&format=json"
)

# Matches dates like "January 1, 2024" or "March 11, 2024"
_DATE_RE = re.compile(
    r"(January|February|March|April|May|June|July|August|September|October|November|December)"
    r"\s+(\d{1,2}),?\s+(\d{4})"
)

_MONTH_MAP = {
    "January": 1,
    "February": 2,
    "March": 3,
    "April": 4,
    "May": 5,
    "June": 6,
    "July": 7,
    "August": 8,
    "September": 9,
    "October": 10,
    "November": 11,
    "December": 12,
}

# Matches card action lines like "Fury is banned" or "Grief is unbanned"
_ACTION_RE = re.compile(
    r"([A-Z][A-Za-z',\s\-]+?)\s+(?:is|are)\s+"
    r"(banned|unbanned|restricted|unrestricted|suspended)",
    re.IGNORECASE,
)

# Format patterns found in the wiki headings
_FORMAT_RE = re.compile(
    r"(Standard|Modern|Legacy|Vintage|Pioneer|Pauper|Historic|Alchemy|Brawl"
    r"|Commander|Explorer|Penny Dreadful)",
    re.IGNORECASE,
)


def _strip_html(text: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r"<[^>]+>", "", text)


def _parse_wiki_html(html: str) -> list[dict]:
    """Parse B&R events from wiki HTML.

    Strategy: split on heading tags (h2/h3) to find date headings and
    format sub-headings, then look for card action text within each
    section. Best-effort; collects what it can and skips the rest.
    """
    events: list[dict] = []

    # Split the HTML into sections by h2/h3 headings
    # Each section starts with a heading and contains the content until the next heading
    sections = re.split(r"(<h[23][^>]*>.*?</h[23]>)", html, flags=re.DOTALL)

    current_date: date | None = None
    current_description = ""
    current_format: str | None = None
    current_actions: list[dict] = []

    def _flush() -> None:
        nonlocal current_format, current_actions
        if current_date and current_format and current_actions:
            events.append(
                {
                    "format": current_format,
                    "effective_date": current_date,
                    "description": current_description,
                    "card_actions": list(current_actions),
                }
            )
        current_actions = []

    for section in sections:
        stripped = _strip_html(section).strip()
        if not stripped:
            continue

        # Check if this is a heading
        is_h2 = "<h2" in section
        is_h3 = "<h3" in section

        if is_h2:
            # h2 headings contain dates
            _flush()
            current_format = None
            date_match = _DATE_RE.search(stripped)
            if date_match:
                month_name, day_str, year_str = date_match.groups()
                try:
                    current_date = date(int(year_str), _MONTH_MAP[month_name], int(day_str))
                    current_description = stripped.strip()
                except (ValueError, KeyError):
                    current_date = None
                    current_description = ""
            else:
                current_date = None
                current_description = ""
            continue

        if is_h3:
            # h3 headings contain format names
            _flush()
            fmt_match = _FORMAT_RE.search(stripped)
            current_format = fmt_match.group(1) if fmt_match else None
            continue

        # Content section — look for card actions
        if current_date is None:
            continue

        plain = _strip_html(section)
        for action_match in _ACTION_RE.finditer(plain):
            card_name = action_match.group(1).strip()
            action = action_match.group(2).lower()
            # Skip overly long matches (likely parsing artifacts)
            if len(card_name) > 100:
                continue
            current_actions.append({"card": card_name, "action": action})

        # If we don't have a format from an h3 but have actions,
        # try to detect format from the content
        if current_format is None and current_actions:
            fmt_match = _FORMAT_RE.search(plain)
            if fmt_match:
                current_format = fmt_match.group(1)

    # Flush any remaining
    _flush()

    return events


@router.post("/import-wiki", response_model=WikiImportResult)
async def import_wiki(
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> WikiImportResult:
    """Fetch the MTG wiki B&R timeline and import events.

    Uses the MediaWiki API for cleaner HTML. Deduplicates on
    (format, effective_date) — existing events are skipped.
    """
    result = WikiImportResult()

    # Fetch wiki page via MediaWiki API
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(_WIKI_API_URL)
        resp.raise_for_status()
        data = resp.json()
        html = data.get("parse", {}).get("text", {}).get("*", "")
        if not html:
            result.errors.append("Wiki API returned empty page content")
            return result
    except httpx.HTTPError as exc:
        result.errors.append(f"Failed to fetch wiki page: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"Wiki fetch error: {exc}")
        return result

    # Parse events from HTML
    try:
        parsed_events = _parse_wiki_html(html)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"Wiki parse error: {exc}")
        return result

    if not parsed_events:
        result.errors.append("No B&R events found in wiki page")
        return result

    # Load existing (format, effective_date) pairs for dedup
    existing_rows = (await db.execute(select(BnrEvent.format, BnrEvent.effective_date))).all()
    existing_keys = {(row[0].lower(), row[1]) for row in existing_rows}

    for evt in parsed_events:
        fmt = evt["format"]
        eff_date = evt["effective_date"]
        key = (fmt.lower(), eff_date)

        if key in existing_keys:
            result.skipped += 1
            continue

        try:
            row = BnrEvent(
                id=uuid.uuid4(),
                format=fmt,
                effective_date=eff_date,
                description=evt["description"],
                card_actions=evt["card_actions"],
            )
            db.add(row)
            await db.flush()
            existing_keys.add(key)
            result.imported += 1
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            result.errors.append(f"Failed to import {fmt} {eff_date}: {exc}")

    await db.commit()

    _log.info(
        "wiki import complete: imported=%d skipped=%d errors=%d",
        result.imported,
        result.skipped,
        len(result.errors),
    )
    return result
