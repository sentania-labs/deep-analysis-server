"""mtgtop8.com competitive-event results scraper.

Fetches the "LAST 20 EVENTS" per format from ``https://www.mtgtop8.com/format?f=XX``,
then parses each event page for player names, placements, and decklists.
Events and per-player decklists land in ``analytics.mtgtop8_events`` and
``analytics.mtgtop8_results``.

Architecture follows the same pattern as :mod:`mtgo_scraper`:

- Pure extraction functions that never raise on bad input — they return
  empty lists and log diagnostics.
- Multi-strategy extraction (primary + fallback).
- Polite delays between requests (2 s between page fetches).
- Descriptive User-Agent.
- ``run_scrape()`` orchestrator that returns a ``ScrapeResult``.
- Health tracked in ``analytics.scraper_health`` keyed by ``scraper_name="mtgtop8"``.

Formats scraped: Vintage, Legacy, Modern, Pioneer, Pauper.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
from datetime import date
from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup, Tag
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Re-use health functions from the MTGO scraper — they're generic by design.
from analytics_service.mtgo_scraper import (
    get_health,
    record_health,
)

_log = logging.getLogger("analytics.mtgtop8_scraper")

USER_AGENT = "DeepAnalysis/0.9 (personal MTGO analytics; contact: ops@sentania.net)"
BASE_URL = "https://www.mtgtop8.com"
REQUEST_TIMEOUT = 60.0
POLITE_DELAY_SECONDS = 2.0
BROKEN_THRESHOLD = 3
SCRAPER_NAME = "mtgtop8"
_SNIPPET_CHARS = 2000

# Format codes used in mtgtop8.com URLs.
FORMATS: dict[str, str] = {
    "VI": "Vintage",
    "LE": "Legacy",
    "MO": "Modern",
    "PI": "Pioneer",
    "PAU": "Pauper",
}

# Regex to extract event IDs from hrefs like "event?e=12345&f=MO"
_EVENT_HREF_RE = re.compile(r"event\?e=(\d+)")
# Regex to extract deck IDs from hrefs like "?e=12345&d=67890&f=MO"
_DECK_HREF_RE = re.compile(r"[?&]d=(\d+)")
# Regex to match date strings like "01/05/26" or "1/5/26" (DD/MM/YY)
_DATE_RE = re.compile(r"(\d{1,2})/(\d{1,2})/(\d{2,4})")
# Regex to extract placement like "1st", "2nd", "#3", etc.
_PLACEMENT_RE = re.compile(r"(\d+)")
# Regex for card lines like "4 Lightning Bolt" or "1x Brainstorm"
_CARD_LINE_RE = re.compile(r"^\s*(\d+)\s*[xX]?\s+(.+?)\s*$")


@dataclasses.dataclass
class ScrapeResult:
    events_found: int = 0
    events_new: int = 0
    events_empty: int = 0
    results_stored: int = 0
    consecutive_failures: int = 0
    is_broken: bool = False
    error: str | None = None


# --------------------------------------------------------------------------- #
# Pure HTML extraction
# --------------------------------------------------------------------------- #


def extract_events_from_format_page(html: str, format_code: str) -> list[dict[str, Any]]:
    """Parse a format listing page into a list of event dicts.

    Returns dicts of the shape::

        {"event_name": str, "format": str, "event_date": date | None,
         "event_url": str, "event_id": str, "format_code": str,
         "player_count": int | None}

    Pure function — no HTTP, no DB, never raises.
    """
    if not html or not html.strip():
        return []

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001
        _log.exception("mtgtop8 format page: BeautifulSoup parse failed")
        return []

    events = _extract_events_strategy_table(soup, format_code)
    if events:
        _log.debug(
            "mtgtop8 format page: table strategy matched",
            extra={"event_count": len(events), "format_code": format_code},
        )
        return events

    events = _extract_events_strategy_anchors(soup, format_code)
    if events:
        _log.debug(
            "mtgtop8 format page: anchor strategy matched",
            extra={"event_count": len(events), "format_code": format_code},
        )
        return events

    _log.warning(
        "mtgtop8 format page: no events extracted by any strategy",
        extra={
            "format_code": format_code,
            "html_snippet": html[:_SNIPPET_CHARS],
        },
    )
    return []


def _extract_events_strategy_table(soup: BeautifulSoup, format_code: str) -> list[dict[str, Any]]:
    """Primary strategy: event rows in table structures.

    mtgtop8.com lists events in table rows with links to ``event?e=ID``.
    Each row typically has the event name, date, and player count.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    format_name = FORMATS.get(format_code, format_code)

    for anchor in soup.find_all("a", href=_EVENT_HREF_RE):
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        match = _EVENT_HREF_RE.search(href)
        if not match:
            continue
        event_id = match.group(1)
        if event_id in seen:
            continue
        seen.add(event_id)

        event_url = urljoin(BASE_URL + "/", href)
        name = anchor.get_text(strip=True)
        if not name:
            continue

        # Walk up to the parent row to find date and player count
        event_date: date | None = None
        player_count: int | None = None
        parent_row = anchor.find_parent("tr")
        if isinstance(parent_row, Tag):
            row_text = parent_row.get_text(" ", strip=True)
            event_date = _parse_date(row_text)
            player_count = _parse_player_count(row_text)

        out.append(
            {
                "event_name": name,
                "format": format_name,
                "event_date": event_date,
                "event_url": event_url,
                "event_id": event_id,
                "format_code": format_code,
                "player_count": player_count,
            }
        )
    return out


def _extract_events_strategy_anchors(soup: BeautifulSoup, format_code: str) -> list[dict[str, Any]]:
    """Fallback: any anchor matching event?e=ID pattern."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    format_name = FORMATS.get(format_code, format_code)

    for anchor in soup.find_all("a", href=True):
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        match = _EVENT_HREF_RE.search(href)
        if not match:
            continue
        event_id = match.group(1)
        if event_id in seen:
            continue
        seen.add(event_id)

        name = anchor.get_text(strip=True)
        if not name or len(name) < 3:
            continue

        event_url = urljoin(BASE_URL + "/", href)
        out.append(
            {
                "event_name": name,
                "format": format_name,
                "event_date": None,
                "event_url": event_url,
                "event_id": event_id,
                "format_code": format_code,
                "player_count": None,
            }
        )
    return out


def extract_decklists_from_event_page(html: str, event_url: str) -> list[dict[str, Any]]:
    """Parse a single event page into per-player decklist dicts.

    Returns dicts of the shape::

        {"player_name": str, "placement": int | None,
         "decklist_main": dict[str, int],
         "decklist_sideboard": dict[str, int],
         "deck_name": str | None}

    Pure function — no HTTP, no DB, never raises.
    """
    if not html or not html.strip():
        return []

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001
        _log.exception(
            "mtgtop8 event page: BeautifulSoup parse failed",
            extra={"event_url": event_url},
        )
        return []

    decklists = _extract_decklists_strategy_player_rows(soup, event_url)
    if decklists:
        return decklists

    decklists = _extract_decklists_strategy_deck_blocks(soup, event_url)
    if decklists:
        return decklists

    _log.warning(
        "mtgtop8 event page: no decklists extracted",
        extra={
            "event_url": event_url,
            "html_snippet": html[:_SNIPPET_CHARS],
        },
    )
    return []


def _extract_decklists_strategy_player_rows(
    soup: BeautifulSoup, event_url: str
) -> list[dict[str, Any]]:
    """Primary strategy: player rows in the event-page div layout.

    mtgtop8 event pages render finisher rows as ``<div class="chosen_tr">``
    (top finisher) and ``<div class="hover_tr">`` (everyone else) — *not*
    real ``<tr>`` table rows. Each row has the shape::

        <div class="chosen_tr"> | <div class="hover_tr">
          <div class="S14">PLACEMENT</div>     <!-- "1", "3-4", "5-8", ... -->
          <div>...thumbnail...</div>
          <div style="flex:1;">
            <div class="S14"><a href="?e=…&d=…">DECK_ARCHETYPE</a></div>
            <div class="G11"><a class="player" href="search?player=…">PLAYER</a></div>
          </div>
        </div>
    """
    out: list[dict[str, Any]] = []
    seen_players: set[str] = set()

    rows = soup.find_all("div", class_=re.compile(r"^(chosen_tr|hover_tr)$"))
    for row in rows:
        if not isinstance(row, Tag):
            continue

        # Each row has two deck anchors with the same href: a thumbnail
        # (image, no text) and a text label. Pick the first one with text.
        deck_name: str | None = None
        for candidate in row.find_all("a", href=_DECK_HREF_RE):
            if not isinstance(candidate, Tag):
                continue
            text_val = candidate.get_text(strip=True)
            if text_val:
                deck_name = text_val
                break
        player_anchor = row.find("a", class_="player")
        if not isinstance(player_anchor, Tag):
            continue
        player_name = player_anchor.get_text(strip=True)
        if not player_name:
            continue

        dedup_key = f"{player_name}:{deck_name}"
        if dedup_key in seen_players:
            continue
        seen_players.add(dedup_key)

        placement = _placement_from_row(row)

        out.append(
            {
                "player_name": player_name,
                "placement": placement,
                "decklist_main": {},
                "decklist_sideboard": {},
                "deck_name": deck_name,
            }
        )

    return out


def _placement_from_row(row: Tag) -> int | None:
    """Pull the leading placement int from a finisher row.

    mtgtop8 prints placement as ``"1"``, ``"3-4"``, ``"5-8"``, ``"9-16"``,
    etc. We collapse ranges to the top finishing position (3 for "3-4").
    """
    # The first <div class="S14"> in the row holds the placement;
    # fall back to any leading "N" / "N-M" text in the row.
    placement_div = row.find("div", class_="S14")
    if isinstance(placement_div, Tag):
        match = _PLACEMENT_RE.match(placement_div.get_text(strip=True))
        if match:
            value = int(match.group(1))
            if 1 <= value <= 999:
                return value
    match = _PLACEMENT_RE.match(row.get_text(" ", strip=True))
    if match:
        value = int(match.group(1))
        if 1 <= value <= 999:
            return value
    return None


def _extract_decklists_strategy_deck_blocks(
    soup: BeautifulSoup, event_url: str
) -> list[dict[str, Any]]:
    """Fallback: look for deck content blocks with card lists.

    Some event pages show decklists inline with card-by-card detail.
    """
    out: list[dict[str, Any]] = []

    # Look for elements that contain card listings
    for block in soup.find_all(attrs={"class": re.compile(r"(deck|list|cards)", re.IGNORECASE)}):
        if not isinstance(block, Tag):
            continue
        deck = _decklist_from_block(block)
        if deck is not None:
            out.append(deck)
    return out


def extract_decklist_from_detail_page(
    html: str, player_name: str, deck_url: str
) -> dict[str, Any] | None:
    """Parse an individual decklist detail page.

    Returns a dict::

        {"player_name": str, "decklist_main": dict[str, int],
         "decklist_sideboard": dict[str, int]}

    or None if parsing fails. Pure function.
    """
    if not html or not html.strip():
        return None

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001
        _log.exception(
            "mtgtop8 deck page: BeautifulSoup parse failed",
            extra={"deck_url": deck_url},
        )
        return None

    main, side = _extract_cards_from_detail(soup)
    if not main and not side:
        _log.debug(
            "mtgtop8 deck page: no cards extracted",
            extra={"deck_url": deck_url, "html_snippet": html[:500]},
        )
        return None

    return {
        "player_name": player_name,
        "decklist_main": main,
        "decklist_sideboard": side,
    }


def _extract_cards_from_detail(soup: BeautifulSoup) -> tuple[dict[str, int], dict[str, int]]:
    """Extract main deck and sideboard cards from a deck detail page.

    mtgtop8 deck pages organize cards by type (Lands, Creatures, etc.)
    with a separate Sideboard section. Cards appear as quantity + name
    in div/span elements or table cells.
    """
    main: dict[str, int] = {}
    side: dict[str, int] = {}
    in_sideboard = False

    # Strategy 1: walk the deck-column container in document order so the
    # SIDEBOARD section header (a sibling ``<div class="O14">SIDEBOARD</div>``,
    # not a deck_line) flips the in_sideboard flag for everything after it.
    deck_columns = _find_deck_column_parents(soup)
    if deck_columns:
        for column in deck_columns:
            for elem in column.find_all("div", recursive=True):
                if not isinstance(elem, Tag):
                    continue
                raw_classes: str | list[str] = elem.get("class") or []
                classes = raw_classes if isinstance(raw_classes, list) else [raw_classes]
                text_content = elem.get_text(" ", strip=True)
                # Section header (LANDS / CREATURES / SIDEBOARD / …) lives
                # in <div class="O14">. Only "SIDEBOARD" flips the board flag.
                if "O14" in classes:
                    if re.search(r"sideboard", text_content, re.IGNORECASE):
                        in_sideboard = True
                    continue
                if "deck_line" not in classes:
                    continue
                match = _CARD_LINE_RE.match(text_content)
                if match:
                    qty = int(match.group(1))
                    name = match.group(2).strip()
                    if qty > 0 and name:
                        target = side if in_sideboard else main
                        target[name] = target.get(name, 0) + qty
        if main or side:
            return main, side

    # Strategy 2: look for all text that matches card line patterns,
    # with sideboard delimited by "Sideboard" heading
    in_sideboard = False
    body_text = soup.get_text("\n")
    for line in body_text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^sideboard\s*$", stripped, re.IGNORECASE):
            in_sideboard = True
            continue
        # Reset on major section headers that aren't sideboard
        match = _CARD_LINE_RE.match(stripped)
        if match:
            qty = int(match.group(1))
            name = match.group(2).strip()
            if qty > 0 and name and not _looks_like_non_card(name):
                target = side if in_sideboard else main
                target[name] = target.get(name, 0) + qty

    return main, side


def _find_deck_column_parents(soup: BeautifulSoup) -> list[Tag]:
    """Return the smallest containers that hold both deck_line cards and
    the SIDEBOARD section header.

    mtgtop8 deck pages render mainboard + sideboard inside a single flex
    column. Walking that column in document order lets the SIDEBOARD
    header act as a separator. We pick the narrowest ancestor so adjacent
    page chrome (sidebar, related decks) doesn't bleed in.
    """
    deck_lines = soup.find_all("div", class_="deck_line")
    if not deck_lines:
        return []
    columns: list[Tag] = []
    seen: set[int] = set()
    for deck_line in deck_lines:
        if not isinstance(deck_line, Tag):
            continue
        parent = deck_line.parent
        if not isinstance(parent, Tag):
            continue
        if id(parent) in seen:
            continue
        seen.add(id(parent))
        columns.append(parent)
    return columns


def _looks_like_non_card(name: str) -> bool:
    """Heuristic: reject strings that are unlikely to be card names."""
    # Reject pure numbers, very short tokens, HTML artifacts
    if len(name) < 2:
        return True
    if name.isdigit():
        return True
    return "<" in name or ">" in name


def _decklist_from_block(block: Tag) -> dict[str, Any] | None:
    """Extract a single decklist from a block element."""
    main: dict[str, int] = {}
    side: dict[str, int] = {}
    in_sideboard = False

    for elem in block.find_all(["li", "p", "div", "span"]):
        if not isinstance(elem, Tag):
            continue
        text_blob = elem.get_text(" ", strip=True)
        if not text_blob:
            continue
        if re.match(r"^sideboard\s*$", text_blob, re.IGNORECASE):
            in_sideboard = True
            continue
        match = _CARD_LINE_RE.match(text_blob)
        if match:
            qty = int(match.group(1))
            name = match.group(2).strip()
            if qty > 0 and name:
                target = side if in_sideboard else main
                target[name] = target.get(name, 0) + qty

    if not main and not side:
        return None

    player = _extract_player_from_block(block)
    return {
        "player_name": player or "Unknown",
        "placement": None,
        "decklist_main": main,
        "decklist_sideboard": side,
        "deck_name": None,
    }


def _extract_player_from_block(block: Tag) -> str | None:
    """Try to find a player name within or near a deck block."""
    for tag in ("h2", "h3", "h4", "b", "strong"):
        heading = block.find(tag)
        if isinstance(heading, Tag):
            text_blob = heading.get_text(strip=True)
            if text_blob and len(text_blob) < 60:
                return text_blob
    return None


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _parse_date(text_value: str) -> date | None:
    """Parse dates from mtgtop8's DD/MM/YY format."""
    if not text_value:
        return None
    match = _DATE_RE.search(text_value)
    if not match:
        return None
    try:
        day = int(match.group(1))
        month = int(match.group(2))
        year = int(match.group(3))
        if year < 100:
            year += 2000
        return date(year, month, day)
    except ValueError:
        return None


def _parse_player_count(text_value: str) -> int | None:
    """Try to extract a player count from row text like '128 players'."""
    match = re.search(r"(\d+)\s*players?", text_value, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


_RETRY_ATTEMPTS = 2
_RETRY_BACKOFF_SECONDS = 5.0


async def _get_with_retry(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET *url* with a single retry on timeout errors."""
    last_exc: httpx.TimeoutException | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            return await client.get(url)
        except httpx.TimeoutException as exc:
            last_exc = exc
            if attempt + 1 < _RETRY_ATTEMPTS:
                _log.warning(
                    "request timed out, retrying in %.0fs url=%s attempt=%d",
                    _RETRY_BACKOFF_SECONDS,
                    url,
                    attempt + 1,
                )
                await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
    raise last_exc  # type: ignore[misc]


async def fetch_format_page(client: httpx.AsyncClient, format_code: str) -> tuple[int, str]:
    """Fetch the format listing page."""
    url = f"{BASE_URL}/format?f={format_code}"
    response = await _get_with_retry(client, url)
    return response.status_code, response.text


async def fetch_event_page(client: httpx.AsyncClient, url: str) -> tuple[int, str]:
    """Fetch a single event page after a polite delay."""
    await asyncio.sleep(POLITE_DELAY_SECONDS)
    response = await _get_with_retry(client, url)
    return response.status_code, response.text


async def fetch_deck_page(
    client: httpx.AsyncClient, event_id: str, deck_id: str, format_code: str
) -> tuple[int, str]:
    """Fetch an individual decklist page after a polite delay."""
    await asyncio.sleep(POLITE_DELAY_SECONDS)
    url = f"{BASE_URL}/event?e={event_id}&d={deck_id}&f={format_code}"
    response = await _get_with_retry(client, url)
    return response.status_code, response.text


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #


_KNOWN_URLS_SQL = text("SELECT event_url FROM analytics.mtgtop8_events")

_INSERT_EVENT_SQL = text(
    """
    INSERT INTO analytics.mtgtop8_events
        (event_name, format, event_date, event_url, player_count)
    VALUES
        (:event_name, :format, :event_date, :event_url, :player_count)
    ON CONFLICT (event_url) DO NOTHING
    RETURNING id
    """
)

_INSERT_RESULT_SQL = text(
    """
    INSERT INTO analytics.mtgtop8_results
        (event_id, player_name, placement, deck_name,
         decklist_main, decklist_sideboard)
    VALUES
        (:event_id, :player_name, :placement, :deck_name,
         CAST(:decklist_main AS jsonb), CAST(:decklist_sideboard AS jsonb))
    """
)


async def get_known_event_urls(session: AsyncSession) -> set[str]:
    rows = (await session.execute(_KNOWN_URLS_SQL)).scalars().all()
    return set(rows)


async def store_event(
    session: AsyncSession,
    event_data: dict[str, Any],
    results: list[dict[str, Any]],
) -> int:
    """Insert event + per-player results. Returns count of results stored.

    If *results* is empty the event is **not** inserted — an event row
    with ``scraped_at`` set but zero result rows looks like a successful
    scrape in the admin UI ("scraped" status, "no results available")
    when it actually means extraction failed.
    """
    if not results:
        _log.warning(
            "mtgtop8 store_event: skipping event with zero results (extraction likely failed)",
            extra={
                "event_url": event_data.get("event_url"),
                "event_name": event_data.get("event_name"),
            },
        )
        return 0
    event_id = (
        await session.execute(
            _INSERT_EVENT_SQL,
            {
                "event_name": event_data["event_name"],
                "format": event_data["format"],
                "event_date": event_data.get("event_date"),
                "event_url": event_data["event_url"],
                "player_count": event_data.get("player_count"),
            },
        )
    ).scalar()
    if event_id is None:
        return 0
    rows = [
        {
            "event_id": event_id,
            "player_name": r["player_name"],
            "placement": r.get("placement"),
            "deck_name": r.get("deck_name"),
            "decklist_main": json.dumps(r.get("decklist_main") or {}),
            "decklist_sideboard": json.dumps(r.get("decklist_sideboard") or {}),
        }
        for r in results
    ]
    await session.execute(_INSERT_RESULT_SQL, rows)
    return len(rows)


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


async def run_scrape(sm: async_sessionmaker[AsyncSession]) -> ScrapeResult:
    """Run one full scrape across all configured formats. Never raises."""
    _log.info("mtgtop8 scrape starting")
    result = ScrapeResult()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }
    last_html_snippet: str | None = None

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            follow_redirects=True,
            cookies=httpx.Cookies(),
        ) as client:
            all_events: list[dict[str, Any]] = []

            # Phase 1: fetch format listing pages and collect events
            for format_code in FORMATS:
                try:
                    fmt_status, fmt_html = await fetch_format_page(client, format_code)
                    last_html_snippet = fmt_html[:_SNIPPET_CHARS] if fmt_html else None
                    if fmt_status != 200:
                        _log.warning(
                            "mtgtop8 format page non-200",
                            extra={
                                "format_code": format_code,
                                "status": fmt_status,
                            },
                        )
                        continue
                    events = extract_events_from_format_page(fmt_html, format_code)
                    all_events.extend(events)
                    _log.debug(
                        "mtgtop8 format page parsed",
                        extra={
                            "format_code": format_code,
                            "events_found": len(events),
                        },
                    )
                    # Polite delay between format pages
                    await asyncio.sleep(POLITE_DELAY_SECONDS)
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    _log.exception(
                        "mtgtop8 format page fetch failed",
                        extra={"format_code": format_code},
                    )

            result.events_found = len(all_events)

            if not all_events and last_html_snippet:
                _log.warning(
                    "mtgtop8 scrape: all format pages returned 200 but "
                    "zero events parsed; first 500 chars for diagnostics",
                    extra={"html_head": last_html_snippet[:500]},
                )

            # Phase 2: filter to new events and fetch each event page
            async with sm() as session:
                known = await get_known_event_urls(session)
                new_events = [e for e in all_events if e["event_url"] not in known]

                for event_data in new_events:
                    try:
                        ev_status, ev_html = await fetch_event_page(client, event_data["event_url"])
                        if ev_status != 200:
                            _log.warning(
                                "mtgtop8 event page non-200",
                                extra={
                                    "event_url": event_data["event_url"],
                                    "status": ev_status,
                                },
                            )
                            continue

                        decklists = extract_decklists_from_event_page(
                            ev_html, event_data["event_url"]
                        )

                        # Phase 3: for players with empty decklists,
                        # try to fetch the individual deck detail page
                        deck_links = _extract_deck_links(ev_html, event_data.get("event_id", ""))
                        for dl in decklists:
                            if dl["decklist_main"]:
                                continue  # already have cards
                            player = dl["player_name"]
                            deck_info = deck_links.get(player) or deck_links.get(
                                dl.get("deck_name", "")
                            )
                            if not deck_info:
                                continue
                            try:
                                dk_status, dk_html = await fetch_deck_page(
                                    client,
                                    deck_info["event_id"],
                                    deck_info["deck_id"],
                                    event_data.get("format_code", ""),
                                )
                                if dk_status == 200:
                                    detail = extract_decklist_from_detail_page(
                                        dk_html, player, deck_info["url"]
                                    )
                                    if detail:
                                        dl["decklist_main"] = detail["decklist_main"]
                                        dl["decklist_sideboard"] = detail["decklist_sideboard"]
                            except asyncio.CancelledError:
                                raise
                            except Exception:  # noqa: BLE001
                                _log.debug(
                                    "mtgtop8 deck page fetch failed",
                                    extra={"player": player},
                                )

                        stored = await store_event(session, event_data, decklists)
                        if stored > 0:
                            result.events_new += 1
                            result.results_stored += stored
                        else:
                            result.events_empty += 1
                    except asyncio.CancelledError:
                        raise
                    except Exception:  # noqa: BLE001
                        _log.exception(
                            "mtgtop8 event processing failed",
                            extra={"event_url": event_data["event_url"]},
                        )

                await session.commit()

        # Treat zero events across ALL formats as a parse failure
        if result.events_found == 0:
            async with sm() as session:
                await record_health(
                    session,
                    SCRAPER_NAME,
                    success=False,
                    error="all format pages returned 200 but zero events parsed",
                    raw_snippet=last_html_snippet,
                )
                health = await get_health(session, SCRAPER_NAME)
            result.consecutive_failures = int(health.get("consecutive_failures") or 0)
            result.is_broken = bool(health.get("is_broken"))
            result.error = "no events parsed"
            _log.warning(
                "mtgtop8 scrape parsed zero events",
                extra={"consecutive_failures": result.consecutive_failures},
            )
            return result

        # If we attempted new events but every one had zero results,
        # treat that as an extraction failure so the admin health panel
        # surfaces the problem instead of showing a green "last success."
        if result.events_empty > 0 and result.events_new == 0:
            err = f"{result.events_empty} event(s) fetched but all had zero results"
            async with sm() as session:
                await record_health(
                    session,
                    SCRAPER_NAME,
                    success=False,
                    error=err,
                    raw_snippet=last_html_snippet,
                )
                health = await get_health(session, SCRAPER_NAME)
            result.consecutive_failures = int(health.get("consecutive_failures") or 0)
            result.is_broken = bool(health.get("is_broken"))
            result.error = err
            _log.warning(
                "mtgtop8 scrape: all event extractions empty",
                extra={"events_empty": result.events_empty},
            )
            return result

        async with sm() as session:
            await record_health(session, SCRAPER_NAME, success=True)
        _log.info(
            "mtgtop8 scrape complete",
            extra={
                "events_found": result.events_found,
                "events_new": result.events_new,
                "results_stored": result.results_stored,
            },
        )
        return result

    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 — orchestrator must never raise
        _log.exception("mtgtop8 scrape failed")
        result.error = str(exc) or exc.__class__.__name__
        try:
            async with sm() as session:
                await record_health(
                    session,
                    SCRAPER_NAME,
                    success=False,
                    error=result.error,
                    raw_snippet=last_html_snippet,
                )
                health = await get_health(session, SCRAPER_NAME)
            result.consecutive_failures = int(health.get("consecutive_failures") or 0)
            result.is_broken = bool(health.get("is_broken"))
        except Exception:  # noqa: BLE001
            _log.exception("mtgtop8 scrape: failed to record health")
        return result


def _extract_deck_links(html: str, event_id: str) -> dict[str, dict[str, str]]:
    """Build a mapping of player/deck names to individual deck page URLs.

    Scans the event page HTML for ``?e=EVENT&d=DECK_ID`` links and maps
    them by their anchor text (which is typically the deck archetype or
    player name).
    """
    out: dict[str, dict[str, str]] = {}
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001
        return out

    for anchor in soup.find_all("a", href=_DECK_HREF_RE):
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        match = _DECK_HREF_RE.search(href)
        if not match:
            continue
        deck_id = match.group(1)
        # Extract event_id from the same href
        ev_match = _EVENT_HREF_RE.search(href)
        ev_id = ev_match.group(1) if ev_match else event_id
        text_val = anchor.get_text(strip=True)
        if text_val:
            out[text_val] = {
                "event_id": ev_id,
                "deck_id": deck_id,
                "url": urljoin(BASE_URL + "/", href),
            }
    return out
