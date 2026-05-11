"""Backfill scanner — finds ingested files that were never parsed.

Runs as a periodic task inside the parser service. Queries across
the ingest and parser schemas to find (sha256, user_id) pairs that
exist in ``ingest.user_uploads`` but have no corresponding row in
``parser.matches``, then feeds them through the normal parse pipeline.

This closes the reliability gap in the Redis pub/sub delivery: if the
parser misses a ``file.ingested`` event (downtime, DB outage, Redis
blip), the backfill scan picks it up on the next pass.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from parser_service.consumer import ParserConsumer

_log = logging.getLogger("parser.backfill")

_UNPARSED_SQL = text(
    """
    SELECT DISTINCT u.sha256, u.user_id
      FROM ingest.user_uploads u
      LEFT JOIN parser.matches m
        ON m.sha256 = u.sha256 AND m.user_id = u.user_id
     WHERE m.id IS NULL
     LIMIT :batch_size
    """
)


async def scan_unparsed(
    sm: async_sessionmaker[AsyncSession],
    consumer: ParserConsumer,
    batch_size: int = 100,
) -> int:
    async with sm() as session:
        rows = (await session.execute(_UNPARSED_SQL, {"batch_size": batch_size})).all()

    if not rows:
        return 0

    _log.info("backfill_scan_found", count=len(rows))
    processed = 0
    for sha256, user_id in rows:
        try:
            result = await consumer.handle_event(str(sha256), int(user_id))
            if result is not None:
                processed += 1
        except Exception:  # noqa: BLE001
            _log.exception("backfill_parse_failed", sha256=sha256, user_id=user_id)

    _log.info("backfill_scan_complete", found=len(rows), processed=processed)
    return processed


async def backfill_loop(
    sm: async_sessionmaker[AsyncSession],
    consumer: ParserConsumer,
    interval_seconds: int,
    stop_event: asyncio.Event,
) -> None:
    _log.info("backfill scanner started interval=%ds", interval_seconds)
    while not stop_event.is_set():
        try:
            await scan_unparsed(sm, consumer)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            _log.exception("backfill scan iteration failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
