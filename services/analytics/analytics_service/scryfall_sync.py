"""Scryfall bulk-data card mirror.

Periodically downloads Scryfall's "oracle-cards" bulk data and upserts
it into ``catalog.cards``. The mirror is the analytics service's
local card-metadata source — downstream features (deck displays, art,
oracle-text search) read from this table rather than hitting Scryfall
on every request.

Refresh cadence is governed by ``DA_SCRYFALL_SYNC_INTERVAL_DAYS``
(default 7). The lifespan task in ``main.py`` checks on startup and
re-checks on a sleep loop; an admin can also trigger a manual sync via
``POST /analytics/admin/sync-cards``.

Implementation note — JSON streaming
------------------------------------
The bulk-data file is ~80MB and is a single top-level JSON array. We
download it to a NamedTemporaryFile and then stream-parse from disk
with sync ``ijson.items``. Two reasons over an httpx → ijson async
pipeline:

1. ``ijson.items_async`` wants an async file-like with an ``async
   read()`` method; ``httpx.Response.aiter_bytes()`` is an async
   iterator of chunks. Bridging the two needs a buffering adapter
   that earns its keep only on a memory-constrained host — and
   80MB on disk doesn't qualify.
2. The download phase is network-bound, the parse phase is CPU-bound.
   Splitting them keeps each phase simple and easy to observe in logs.

Memory stays flat (~80MB on disk, ~constant in process). The sync
``ijson`` iteration runs on the event loop thread; this is acceptable
because the sync runs as a background task at a 7-day cadence, not on
a user-facing request path. If the periodic blocking ever bites,
wrap ``ijson.items`` in ``asyncio.to_thread`` per batch.
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import ijson
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from analytics_service.settings import get_settings

_log = logging.getLogger("analytics.scryfall_sync")

_BULK_DATA_URL = "https://api.scryfall.com/bulk-data/oracle-cards"
_USER_AGENT = "DeepAnalysis/0.7.5 (self-hosted analytics; contact: admin)"
_BATCH_SIZE = 500
_HTTP_TIMEOUT = httpx.Timeout(30.0, read=300.0)


@dataclass
class SyncResult:
    cards_upserted: int
    synced_at: datetime


_UPSERT_SQL = text(
    """
    INSERT INTO catalog.cards (
        scryfall_id, oracle_id, mtgo_id, name, oracle_text, type_line,
        mana_cost, colors, set_code, image_uri, art_crop_uri,
        legalities, synced_at
    ) VALUES (
        :scryfall_id, CAST(:oracle_id AS uuid), :mtgo_id, :name,
        :oracle_text, :type_line, :mana_cost,
        CAST(:colors AS jsonb), :set_code, :image_uri, :art_crop_uri,
        CAST(:legalities AS jsonb), :synced_at
    )
    ON CONFLICT (scryfall_id) DO UPDATE SET
        oracle_id = EXCLUDED.oracle_id,
        mtgo_id = EXCLUDED.mtgo_id,
        name = EXCLUDED.name,
        oracle_text = EXCLUDED.oracle_text,
        type_line = EXCLUDED.type_line,
        mana_cost = EXCLUDED.mana_cost,
        colors = EXCLUDED.colors,
        set_code = EXCLUDED.set_code,
        image_uri = EXCLUDED.image_uri,
        art_crop_uri = EXCLUDED.art_crop_uri,
        legalities = EXCLUDED.legalities,
        synced_at = EXCLUDED.synced_at
    """
)


def _card_row(card: dict[str, Any], synced_at: datetime) -> dict[str, Any]:
    """Project a raw Scryfall card object onto the columns we persist.

    Several fields are routinely absent — double-faced cards, for
    instance, store ``image_uris`` per face rather than at the top
    level. We persist null in that case rather than synthesizing a
    face URI; consumers that need face-aware art can do their own
    Scryfall lookups.
    """
    image_uris = card.get("image_uris") or {}
    colors = card.get("colors")
    legalities = card.get("legalities")
    return {
        "scryfall_id": card["id"],
        "oracle_id": card.get("oracle_id"),
        "mtgo_id": card.get("mtgo_id"),
        "name": card["name"],
        "oracle_text": card.get("oracle_text"),
        "type_line": card.get("type_line"),
        "mana_cost": card.get("mana_cost"),
        # asyncpg's JSONB binding wants a JSON string for raw text();
        # the explicit CAST in the UPSERT SQL handles the cast.
        "colors": _jsonb_param(colors),
        "set_code": card.get("set"),
        "image_uri": image_uris.get("normal"),
        "art_crop_uri": image_uris.get("art_crop"),
        "legalities": _jsonb_param(legalities),
        "synced_at": synced_at,
    }


def _jsonb_param(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value)


async def _upsert_batch(session: AsyncSession, batch: list[dict[str, Any]]) -> None:
    await session.execute(_UPSERT_SQL, batch)


async def fetch_bulk_data_uri(client: httpx.AsyncClient) -> str:
    """Resolve the current ``oracle-cards`` download URI from Scryfall.

    Scryfall's bulk-data manifest changes the download URI on each
    refresh, so we look it up fresh every sync rather than caching.
    """
    response = await client.get(_BULK_DATA_URL)
    response.raise_for_status()
    payload = response.json()
    download_uri = payload.get("download_uri")
    if not download_uri:
        raise RuntimeError("scryfall bulk-data response missing download_uri")
    return str(download_uri)


async def stream_sync_cards(
    session: AsyncSession,
    download_uri: str,
    client: httpx.AsyncClient,
) -> SyncResult:
    """Download the bulk-data file and upsert in batches of 500."""
    synced_at = datetime.now(UTC)
    cards_upserted = 0

    with tempfile.NamedTemporaryFile(suffix=".json", mode="w+b") as tmp:
        async with client.stream("GET", download_uri) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                tmp.write(chunk)
        tmp.flush()
        tmp.seek(0)

        batch: list[dict[str, Any]] = []
        for card in ijson.items(tmp, "item"):
            batch.append(_card_row(card, synced_at))
            if len(batch) >= _BATCH_SIZE:
                await _upsert_batch(session, batch)
                cards_upserted += len(batch)
                batch = []
        if batch:
            await _upsert_batch(session, batch)
            cards_upserted += len(batch)

    await session.commit()
    return SyncResult(cards_upserted=cards_upserted, synced_at=synced_at)


async def should_sync(session: AsyncSession) -> bool:
    """True if ``catalog.cards`` is empty, stale, or missing legality data."""
    settings = get_settings()
    last = (
        await session.execute(text("SELECT MAX(synced_at) FROM catalog.cards"))
    ).scalar_one_or_none()
    if last is None:
        return True
    cutoff = datetime.now(UTC) - timedelta(days=settings.scryfall_sync_interval_days)
    if last < cutoff:
        return True
    has_legalities = (
        await session.execute(
            text("SELECT EXISTS(SELECT 1 FROM catalog.cards WHERE legalities IS NOT NULL)")
        )
    ).scalar_one()
    return not has_legalities


async def run_sync(sessionmaker: async_sessionmaker[AsyncSession]) -> SyncResult:
    """Orchestrate a full Scryfall sync.

    Opens its own DB session and HTTP client — designed to be called
    standalone (admin endpoint) or from the lifespan scheduler.
    """
    _log.info("scryfall sync starting")
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, headers=headers) as client:
        download_uri = await fetch_bulk_data_uri(client)
        _log.info("scryfall bulk-data resolved", extra={"download_uri": download_uri})
        async with sessionmaker() as session:
            result = await stream_sync_cards(session, download_uri, client)
    _log.info(
        "scryfall sync complete",
        extra={
            "cards_upserted": result.cards_upserted,
            "synced_at": result.synced_at.isoformat(),
        },
    )
    return result
