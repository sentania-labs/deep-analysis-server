"""Backfill scanner — finds ingested files that were never parsed.

Runs as a periodic task inside the parser service. Queries across
the ingest and parser schemas to find (sha256, user_id) pairs that
exist in ``ingest.user_uploads`` but have no corresponding row in
``parser.matches``, then feeds them through the normal parse pipeline.

This closes the reliability gap in the Redis pub/sub delivery: if the
parser misses a ``file.ingested`` event (downtime, DB outage, Redis
blip), the backfill scan picks it up on the next pass.

Additionally, matches where ``parsed_with_version`` is NULL or older
than :data:`~parser_service.settings.REPARSE_MIN_VERSION` are queued
for reparse so that parser improvements can be applied retroactively.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from parser_service.consumer import ParserConsumer
from parser_service.settings import REPARSE_MIN_VERSION, get_settings

_log = logging.getLogger("parser.backfill")

_UNPARSED_SQL = text(
    """
    SELECT u.sha256, u.user_id
      FROM ingest.user_uploads u
      JOIN ingest.game_log_files g ON g.sha256 = u.sha256
      LEFT JOIN parser.matches m
        ON m.sha256 = u.sha256 AND m.user_id = u.user_id
     WHERE g.content_type = 'match-log'
       AND (
           m.id IS NULL
           OR m.parsed_with_version IS NULL
           OR m.parsed_with_version < :min_version
       )
     GROUP BY u.sha256, u.user_id
     ORDER BY MAX(u.uploaded_at) DESC
     LIMIT :batch_size
    """
)


async def scan_unparsed(
    sm: async_sessionmaker[AsyncSession],
    consumer: ParserConsumer,
    batch_size: int | None = None,
) -> int:
    if batch_size is None:
        batch_size = get_settings().backfill_batch_size
    async with sm() as session:
        rows = (
            await session.execute(
                _UNPARSED_SQL,
                {"batch_size": batch_size, "min_version": REPARSE_MIN_VERSION},
            )
        ).all()

    if not rows:
        return 0

    _log.info("backfill scan found %d unparsed files", len(rows))
    processed = 0
    for sha256, user_id in rows:
        try:
            result = await consumer.handle_event(str(sha256), int(user_id))
            if result is not None:
                processed += 1
        except Exception:  # noqa: BLE001
            _log.exception("backfill parse failed sha256=%s user_id=%s", sha256, user_id)

    _log.info("backfill scan complete found=%d processed=%d", len(rows), processed)
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
