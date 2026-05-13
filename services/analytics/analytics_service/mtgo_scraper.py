"""MTGO public-event results scraper.

Fetches ``https://www.mtgo.com/decklists`` (the WotC-published event
listing), parses the event index, then fetches and parses each
individual event page. Events and per-player decklists land in the
``analytics.mtgo_events`` and ``analytics.mtgo_results`` tables.

Design principle — make breakage obvious
----------------------------------------
mtgo.com is server-rendered and has no public API. The HTML shape is
not a contract; it changes whenever WotC reskins the page. So all
extraction lives in clearly named pure functions
(``extract_events_from_html``, ``extract_decklists_from_html``) — when
something stops working, the function name tells you exactly where to
look. The functions never raise on bad input; they return empty lists
and log what they expected vs. what they found, plus a snippet of raw
HTML for the next debugger.

Health is tracked in ``analytics.scraper_health`` keyed by scraper
name. Three consecutive zero-event scrapes flips ``is_broken=true``
and emits a structured warning. The admin endpoint
``GET /analytics/admin/scraper-health`` exposes this for monitoring.

Politeness
----------
A descriptive User-Agent identifies us, and ``fetch_event_page``
sleeps ``POLITE_DELAY_SECONDS`` (2s) before each per-event request so
a full scrape stays well under one request per second on the listing
page. The listing fetch itself is a single hit per scheduled run.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
from datetime import date, datetime
from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup, Tag
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_log = logging.getLogger("analytics.mtgo_scraper")

USER_AGENT = "DeepAnalysis/0.8 (personal MTGO analytics; contact: ops@sentania.net)"
LISTING_URL = "https://www.mtgo.com/decklists"
REQUEST_TIMEOUT = 60.0
POLITE_DELAY_SECONDS = 2.0
BROKEN_THRESHOLD = 3
SCRAPER_NAME = "mtgo"
_SNIPPET_CHARS = 2000

_EVENT_HREF_RE = re.compile(r"/decklist/", re.IGNORECASE)
_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
# mtgo.com URLs include the date in the slug, e.g.
# /decklist/modern-challenge-2026-05-08
_DATE_IN_SLUG_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_FORMAT_TOKENS = (
    "standard",
    "pioneer",
    "modern",
    "legacy",
    "vintage",
    "pauper",
    "limited",
    "draft",
    "sealed",
    "historic",
    "explorer",
    "alchemy",
    "timeless",
    "premodern",
)
_PLACEMENT_RE = re.compile(r"(\d+)")


@dataclasses.dataclass
class ScrapeResult:
    events_found: int = 0
    events_new: int = 0
    results_stored: int = 0
    consecutive_failures: int = 0
    is_broken: bool = False
    error: str | None = None


# --------------------------------------------------------------------------- #
# Pure HTML extraction
# --------------------------------------------------------------------------- #


def extract_events_from_html(html: str) -> list[dict[str, Any]]:
    """Parse the listing HTML into a list of event dicts.

    Returns dicts of the shape::

        {"event_name": str, "format": str | None,
         "event_date": datetime.date | None, "event_url": str}

    Pure function — no HTTP, no DB, never raises. On any failure logs
    what was expected vs. found and returns an empty list.
    """
    if not html or not html.strip():
        return []

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001 — defensive, BS rarely raises
        _log.exception("mtgo listing: BeautifulSoup parse failed")
        return []

    events = _extract_events_strategy_anchors(soup)
    if events:
        _log.debug(
            "mtgo listing: anchor strategy matched",
            extra={"event_count": len(events)},
        )
        return events

    events = _extract_events_strategy_decklist_class(soup)
    if events:
        _log.debug(
            "mtgo listing: class-name strategy matched",
            extra={"event_count": len(events)},
        )
        return events

    events = _extract_events_strategy_articles(soup)
    if events:
        _log.debug(
            "mtgo listing: article/section strategy matched",
            extra={"event_count": len(events)},
        )
        return events

    _log.warning(
        "mtgo listing: no events extracted by any strategy",
        extra={
            "expected": (
                "anchors with href matching /decklist/, "
                "elements with class containing 'decklist' or 'event', "
                "or article/section with date-like text"
            ),
            "html_snippet": html[:_SNIPPET_CHARS],
        },
    )
    return []


def _extract_events_strategy_anchors(soup: BeautifulSoup) -> list[dict[str, Any]]:
    """Primary strategy: ``<a href="/decklist/...">`` style links."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=_EVENT_HREF_RE):
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        url = urljoin(LISTING_URL, href)
        if url in seen:
            continue
        seen.add(url)
        name = (anchor.get_text(strip=True) or _slug_to_name(href)).strip()
        if not name:
            name = href
        event_date = _date_from_text(anchor.get_text(" ", strip=True)) or _date_from_slug(href)
        fmt = _format_from_text(name) or _format_from_text(href)
        out.append(
            {
                "event_name": name,
                "format": fmt,
                "event_date": event_date,
                "event_url": url,
            }
        )
    return out


def _extract_events_strategy_decklist_class(
    soup: BeautifulSoup,
) -> list[dict[str, Any]]:
    """Fallback strategy: containers with class containing 'decklist' or 'event'."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    candidates = soup.find_all(attrs={"class": re.compile(r"(decklist|event)", re.IGNORECASE)})
    for elem in candidates:
        if not isinstance(elem, Tag):
            continue
        anchor = elem.find("a", href=True)
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        url = urljoin(LISTING_URL, href)
        if url in seen:
            continue
        seen.add(url)
        text_blob = elem.get_text(" ", strip=True)
        name = (anchor.get_text(strip=True) or text_blob[:120]).strip()
        if not name:
            continue
        out.append(
            {
                "event_name": name,
                "format": _format_from_text(text_blob),
                "event_date": _date_from_text(text_blob) or _date_from_slug(href),
                "event_url": url,
            }
        )
    return out


def _extract_events_strategy_articles(
    soup: BeautifulSoup,
) -> list[dict[str, Any]]:
    """Last-resort strategy: ``<article>``/``<section>`` with date-like text."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for elem in soup.find_all(["article", "section"]):
        if not isinstance(elem, Tag):
            continue
        text_blob = elem.get_text(" ", strip=True)
        event_date = _date_from_text(text_blob)
        if event_date is None:
            continue
        anchor = elem.find("a", href=True)
        if not isinstance(anchor, Tag):
            continue
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        url = urljoin(LISTING_URL, href)
        if url in seen:
            continue
        seen.add(url)
        name = (anchor.get_text(strip=True) or text_blob[:120]).strip()
        if not name:
            continue
        out.append(
            {
                "event_name": name,
                "format": _format_from_text(text_blob),
                "event_date": event_date,
                "event_url": url,
            }
        )
    return out


def extract_decklists_from_html(html: str, event_url: str) -> list[dict[str, Any]]:
    """Parse a single event page into per-player decklist dicts.

    Returns dicts of the shape::

        {"player_name": str, "placement": int | None,
         "decklist_main": dict[str, int],
         "decklist_sideboard": dict[str, int]}

    Pure function — no HTTP, no DB, never raises.
    """
    if not html or not html.strip():
        return []

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # noqa: BLE001
        _log.exception(
            "mtgo event page: BeautifulSoup parse failed",
            extra={"event_url": event_url},
        )
        return []

    decklists = _extract_decklists_strategy_mtgo_js_data(soup)
    if decklists:
        return decklists

    decklists = _extract_decklists_strategy_player_blocks(soup)
    if decklists:
        return decklists

    decklists = _extract_decklists_strategy_embedded_json(soup)
    if decklists:
        return decklists

    _log.warning(
        "mtgo event page: no decklists extracted",
        extra={
            "event_url": event_url,
            "expected": (
                "window.MTGO.decklists.data JS payload, "
                "player blocks with class containing 'deck'/'player', "
                "or an embedded application/json deck payload"
            ),
            "html_snippet": html[:_SNIPPET_CHARS],
        },
    )
    return []


_MTGO_JS_DATA_RE = re.compile(r"window\.MTGO\.decklists\.data\s*=\s*")


def _extract_decklists_strategy_mtgo_js_data(
    soup: BeautifulSoup,
) -> list[dict[str, Any]]:
    """Primary strategy: ``window.MTGO.decklists.data = {...}`` in a script tag.

    mtgo.com renders decklist data as a JS object assignment. The
    ``main_deck`` array contains all cards; each entry's ``sideboard``
    field (string ``"true"``/``"false"``) discriminates board membership.
    """
    for script in soup.find_all("script"):
        if not isinstance(script, Tag):
            continue
        raw = script.string or script.get_text() or ""
        match = _MTGO_JS_DATA_RE.search(raw)
        if not match:
            continue
        json_start = match.end()
        try:
            data, _ = json.JSONDecoder().raw_decode(raw, json_start)
        except (ValueError, TypeError):
            _log.debug(
                "mtgo event page: found MTGO.decklists.data but JSON decode failed",
                extra={"snippet": raw[json_start : json_start + 200]},
            )
            continue
        if not isinstance(data, dict):
            continue
        entries = data.get("decklists")
        if not isinstance(entries, list):
            continue
        return _decklists_from_mtgo_js(entries)
    return []


def _decklists_from_mtgo_js(entries: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        player = entry.get("player")
        if not isinstance(player, str) or not player.strip():
            continue
        main: dict[str, int] = {}
        side: dict[str, int] = {}
        for card in entry.get("main_deck") or []:
            if not isinstance(card, dict):
                continue
            attrs = card.get("card_attributes")
            if not isinstance(attrs, dict):
                continue
            name = attrs.get("card_name")
            if not isinstance(name, str) or not name.strip():
                continue
            try:
                qty = int(card.get("qty", 0))
            except (TypeError, ValueError):
                continue
            if qty <= 0:
                continue
            name = name.strip()
            is_side = str(card.get("sideboard", "false")).lower() == "true"
            target = side if is_side else main
            target[name] = target.get(name, 0) + qty
        if not main and not side:
            continue
        out.append(
            {
                "player_name": player.strip(),
                "placement": None,
                "decklist_main": main,
                "decklist_sideboard": side,
            }
        )
    return out


def _extract_decklists_strategy_player_blocks(
    soup: BeautifulSoup,
) -> list[dict[str, Any]]:
    """Fallback strategy: per-player blocks with mainboard/sideboard sections."""
    out: list[dict[str, Any]] = []
    deck_blocks = soup.find_all(attrs={"class": re.compile(r"(deck|player)", re.IGNORECASE)})
    for block in deck_blocks:
        if not isinstance(block, Tag):
            continue
        deck = _decklist_from_block(block)
        if deck is not None:
            out.append(deck)
    return out


def _decklist_from_block(block: Tag) -> dict[str, Any] | None:
    player = _player_name_from_block(block)
    if not player:
        return None
    main = _cards_from_section(block, kind="main")
    side = _cards_from_section(block, kind="side")
    if not main and not side:
        return None
    return {
        "player_name": player,
        "placement": _placement_from_block(block),
        "decklist_main": main,
        "decklist_sideboard": side,
    }


def _player_name_from_block(block: Tag) -> str | None:
    for tag_name in ("h2", "h3", "h4"):
        heading = block.find(tag_name)
        if isinstance(heading, Tag):
            text_blob = heading.get_text(" ", strip=True)
            if text_blob:
                return _strip_placement(text_blob)
    name_node = block.find(attrs={"class": re.compile(r"player", re.IGNORECASE)})
    if isinstance(name_node, Tag):
        text_blob = name_node.get_text(" ", strip=True)
        if text_blob:
            return _strip_placement(text_blob)
    return None


def _placement_from_block(block: Tag) -> int | None:
    place_node = block.find(attrs={"class": re.compile(r"(place|rank|finish)", re.IGNORECASE)})
    if isinstance(place_node, Tag):
        match = _PLACEMENT_RE.search(place_node.get_text(" ", strip=True))
        if match:
            return int(match.group(1))
    for tag_name in ("h2", "h3", "h4"):
        heading = block.find(tag_name)
        if isinstance(heading, Tag):
            match = _PLACEMENT_RE.search(heading.get_text(" ", strip=True))
            if match:
                value = int(match.group(1))
                if 1 <= value <= 999:
                    return value
    return None


def _cards_from_section(block: Tag, *, kind: str) -> dict[str, int]:
    """Collect card-name → quantity for either mainboard or sideboard."""
    if kind == "main":
        pattern = re.compile(r"main", re.IGNORECASE)
    else:
        pattern = re.compile(r"side", re.IGNORECASE)
    section = block.find(attrs={"class": pattern})
    if not isinstance(section, Tag):
        return {}
    return _parse_card_lines(section)


def _parse_card_lines(section: Tag) -> dict[str, int]:
    out: dict[str, int] = {}
    for li in section.find_all(["li", "p", "div"]):
        if not isinstance(li, Tag):
            continue
        text_blob = li.get_text(" ", strip=True)
        if not text_blob:
            continue
        match = re.match(r"^\s*(\d+)\s*[xX]?\s+(.+?)\s*$", text_blob)
        if not match:
            continue
        qty = int(match.group(1))
        name = match.group(2).strip()
        if not name or qty <= 0:
            continue
        out[name] = out.get(name, 0) + qty
    return out


def _extract_decklists_strategy_embedded_json(
    soup: BeautifulSoup,
) -> list[dict[str, Any]]:
    """Fallback: an embedded ``<script type=application/json>`` deck payload.

    mtgo.com has historically rendered structured deck data into a JSON
    blob; this catches the common shape without committing to it.
    """
    out: list[dict[str, Any]] = []
    for script in soup.find_all("script", attrs={"type": "application/json"}):
        if not isinstance(script, Tag):
            continue
        raw = script.string or script.get_text() or ""
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            continue
        out.extend(_decklists_from_json_payload(data))
    return out


def _decklists_from_json_payload(data: Any) -> list[dict[str, Any]]:
    candidates: list[Any] = []
    if isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        for key in ("decklists", "decks", "results", "players"):
            value = data.get(key)
            if isinstance(value, list):
                candidates = value
                break
    out: list[dict[str, Any]] = []
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        player = entry.get("player") or entry.get("player_name") or entry.get("name")
        if not isinstance(player, str) or not player.strip():
            continue
        main = _cards_from_json(entry.get("main") or entry.get("mainboard") or [])
        side = _cards_from_json(entry.get("sideboard") or entry.get("side") or [])
        if not main and not side:
            continue
        placement_raw = entry.get("placement") or entry.get("place") or entry.get("rank")
        placement: int | None
        try:
            placement = int(placement_raw) if placement_raw is not None else None
        except (TypeError, ValueError):
            placement = None
        out.append(
            {
                "player_name": player.strip(),
                "placement": placement,
                "decklist_main": main,
                "decklist_sideboard": side,
            }
        )
    return out


def _cards_from_json(value: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    if isinstance(value, dict):
        for name, qty in value.items():
            if isinstance(name, str) and isinstance(qty, int) and qty > 0:
                out[name] = qty
        return out
    if isinstance(value, list):
        for entry in value:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or entry.get("card_name") or entry.get("card")
            qty = entry.get("quantity") or entry.get("qty") or entry.get("count")
            if isinstance(name, str) and isinstance(qty, int) and qty > 0:
                out[name] = out.get(name, 0) + qty
    return out


# --------------------------------------------------------------------------- #
# Small text helpers
# --------------------------------------------------------------------------- #


def _slug_to_name(href: str) -> str:
    slug = href.rstrip("/").rsplit("/", 1)[-1]
    return slug.replace("-", " ").replace("_", " ").strip().title()


def _date_from_text(text_value: str) -> date | None:
    if not text_value:
        return None
    match = _DATE_RE.search(text_value)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d").date()
    except ValueError:
        return None


def _date_from_slug(href: str) -> date | None:
    if not href:
        return None
    match = _DATE_IN_SLUG_RE.search(href)
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def _format_from_text(text_value: str) -> str | None:
    if not text_value:
        return None
    lowered = text_value.lower()
    for token in _FORMAT_TOKENS:
        if token in lowered:
            return token.title()
    return None


def _strip_placement(text_value: str) -> str:
    # Drop a leading placement marker like "1st — Player Name" or "12. Foo"
    return re.sub(r"^\s*\d+(st|nd|rd|th)?\s*[\-\.—:]?\s*", "", text_value).strip()


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


_RETRY_ATTEMPTS = 2
_RETRY_BACKOFF_SECONDS = 5.0


async def _get_with_retry(
    client: httpx.AsyncClient,
    url: str,
) -> httpx.Response:
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


async def fetch_event_listing(client: httpx.AsyncClient) -> tuple[int, str]:
    response = await _get_with_retry(client, LISTING_URL)
    return response.status_code, response.text


async def fetch_event_page(client: httpx.AsyncClient, url: str) -> tuple[int, str]:
    """Fetch a single event page after a polite delay."""
    await asyncio.sleep(POLITE_DELAY_SECONDS)
    response = await _get_with_retry(client, url)
    return response.status_code, response.text


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #


_KNOWN_URLS_SQL = text("SELECT event_url FROM analytics.mtgo_events")

_INSERT_EVENT_SQL = text(
    """
    INSERT INTO analytics.mtgo_events
        (event_name, format, event_date, event_url)
    VALUES
        (:event_name, :format, :event_date, :event_url)
    ON CONFLICT (event_url) DO NOTHING
    RETURNING id
    """
)

_INSERT_RESULT_SQL = text(
    """
    INSERT INTO analytics.mtgo_results
        (event_id, player_name, placement, decklist_main, decklist_sideboard)
    VALUES
        (:event_id, :player_name, :placement,
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

    Skips entirely on conflict (already-stored ``event_url``).
    """
    event_id = (await session.execute(_INSERT_EVENT_SQL, event_data)).scalar()
    if event_id is None:
        return 0
    rows = [
        {
            "event_id": event_id,
            "player_name": r["player_name"],
            "placement": r.get("placement"),
            "decklist_main": json.dumps(r.get("decklist_main") or {}),
            "decklist_sideboard": json.dumps(r.get("decklist_sideboard") or {}),
        }
        for r in results
    ]
    if rows:
        await session.execute(_INSERT_RESULT_SQL, rows)
    return len(rows)


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


_HEALTH_SELECT_SQL = text(
    """
    SELECT scraper_name, last_run_at, last_success_at,
           consecutive_failures, is_broken, last_error, last_raw_snippet
      FROM analytics.scraper_health
     WHERE scraper_name = :scraper_name
    """
)

_HEALTH_UPSERT_SUCCESS_SQL = text(
    """
    INSERT INTO analytics.scraper_health
        (scraper_name, last_run_at, last_success_at,
         consecutive_failures, is_broken, last_error, last_raw_snippet)
    VALUES (:scraper_name, now(), now(), 0, FALSE, NULL, NULL)
    ON CONFLICT (scraper_name) DO UPDATE SET
        last_run_at = now(),
        last_success_at = now(),
        consecutive_failures = 0,
        is_broken = FALSE,
        last_error = NULL,
        last_raw_snippet = NULL
    """
)

_HEALTH_UPSERT_FAILURE_SQL = text(
    """
    INSERT INTO analytics.scraper_health
        (scraper_name, last_run_at, last_success_at,
         consecutive_failures, is_broken, last_error, last_raw_snippet)
    VALUES (:scraper_name, now(), NULL, 1,
            (1 >= :broken_threshold), :error, :raw_snippet)
    ON CONFLICT (scraper_name) DO UPDATE SET
        last_run_at = now(),
        consecutive_failures = analytics.scraper_health.consecutive_failures + 1,
        is_broken = (analytics.scraper_health.consecutive_failures + 1)
                    >= :broken_threshold,
        last_error = :error,
        last_raw_snippet = :raw_snippet
    """
)


async def record_health(
    session: AsyncSession,
    scraper_name: str,
    *,
    success: bool,
    error: str | None = None,
    raw_snippet: str | None = None,
) -> None:
    """Upsert the per-scraper health row."""
    if success:
        await session.execute(_HEALTH_UPSERT_SUCCESS_SQL, {"scraper_name": scraper_name})
    else:
        await session.execute(
            _HEALTH_UPSERT_FAILURE_SQL,
            {
                "scraper_name": scraper_name,
                "broken_threshold": BROKEN_THRESHOLD,
                "error": (error or "")[:_SNIPPET_CHARS] or None,
                "raw_snippet": (raw_snippet or "")[:_SNIPPET_CHARS] or None,
            },
        )
    await session.commit()
    if not success:
        health = await get_health(session, scraper_name)
        if health.get("is_broken"):
            _log.warning(
                "scraper marked broken",
                extra={
                    "scraper_name": scraper_name,
                    "consecutive_failures": health.get("consecutive_failures"),
                },
            )


async def get_health(session: AsyncSession, scraper_name: str) -> dict[str, Any]:
    row = (
        (await session.execute(_HEALTH_SELECT_SQL, {"scraper_name": scraper_name}))
        .mappings()
        .one_or_none()
    )
    if row is None:
        return {
            "scraper_name": scraper_name,
            "last_run_at": None,
            "last_success_at": None,
            "consecutive_failures": 0,
            "is_broken": False,
            "last_error": None,
            "last_raw_snippet": None,
        }
    return dict(row)


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


async def run_scrape(sm: async_sessionmaker[AsyncSession]) -> ScrapeResult:
    """Run one full scrape. Never raises — failures land in ScrapeResult."""
    _log.info("mtgo scrape starting")
    result = ScrapeResult()
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    last_html_snippet: str | None = None

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT, headers=headers, follow_redirects=True
        ) as client:
            status, listing_html = await fetch_event_listing(client)
            last_html_snippet = listing_html[:_SNIPPET_CHARS] if listing_html else None
            if status != 200:
                raise RuntimeError(f"mtgo listing returned status {status}")

            events = extract_events_from_html(listing_html)
            result.events_found = len(events)

            async with sm() as session:
                known = await get_known_event_urls(session)
                new_events = [e for e in events if e["event_url"] not in known]

                for event_data in new_events:
                    event_status, event_html = await fetch_event_page(
                        client, event_data["event_url"]
                    )
                    if event_status != 200:
                        _log.warning(
                            "mtgo event page non-200",
                            extra={
                                "event_url": event_data["event_url"],
                                "status": event_status,
                            },
                        )
                        continue
                    decklists = extract_decklists_from_html(event_html, event_data["event_url"])
                    stored = await store_event(session, event_data, decklists)
                    if stored > 0 or decklists:
                        result.events_new += 1
                        result.results_stored += stored
                await session.commit()

        # Treat a 200 listing with zero parsed events as a parse failure —
        # this is the canonical "mtgo.com changed their HTML" signal.
        if result.events_found == 0:
            async with sm() as session:
                await record_health(
                    session,
                    SCRAPER_NAME,
                    success=False,
                    error="listing returned 200 but zero events parsed",
                    raw_snippet=last_html_snippet,
                )
                health = await get_health(session, SCRAPER_NAME)
            result.consecutive_failures = int(health.get("consecutive_failures") or 0)
            result.is_broken = bool(health.get("is_broken"))
            result.error = "no events parsed"
            _log.warning(
                "mtgo scrape parsed zero events",
                extra={"consecutive_failures": result.consecutive_failures},
            )
            return result

        async with sm() as session:
            await record_health(session, SCRAPER_NAME, success=True)
        _log.info(
            "mtgo scrape complete",
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
        _log.exception("mtgo scrape failed")
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
        except Exception:  # noqa: BLE001 — never raise from orchestrator
            _log.exception("mtgo scrape: failed to record health")
        return result
