"""Redis pub/sub consumer for ``file.ingested`` events.

One worker per process. On each event:

1. Read the raw bytes from the shared archive at the published sha.
2. Parse with :class:`LogParser`.
3. Persist into ``parser.matches`` / ``parser.games`` /
   ``parser.game_states`` (idempotent on ``(sha256, user_id)``).
4. Publish ``match.parsed`` so downstream subscribers (analytics,
   AI add-on) can react.

Persistence and publish failures are logged and do not kill the
worker — pub/sub delivery is best-effort, and the goal is to keep
draining events. Hard programmer errors still propagate.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import async_sessionmaker

from common.events import FILE_INGESTED, MATCH_PARSED, FileIngestedPayload, MatchParsedPayload
from common.redis_client import EventPublisher
from parser_service.parsing import LogParser, ParsedMatch
from parser_service.persistence import persist_match
from parser_service.storage import RawFileNotFoundError, RawFileTooLargeError, read_raw

_log = logging.getLogger("parser.consumer")


class ParserConsumer:
    def __init__(
        self,
        redis_client: redis.Redis,
        sessionmaker: async_sessionmaker[Any],
        raw_root: Path,
        parser: LogParser | None = None,
        publisher: EventPublisher | None = None,
        max_log_bytes: int | None = None,
    ) -> None:
        self._redis = redis_client
        self._sessionmaker = sessionmaker
        self._raw_root = raw_root
        self._parser = parser or LogParser()
        self._publisher = publisher or EventPublisher(redis_client)
        self._max_log_bytes = max_log_bytes
        self._stop_event = asyncio.Event()

    def stop(self) -> None:
        """Signal the consumer to stop on the next iteration."""
        self._stop_event.set()

    async def run(self) -> None:
        """Subscribe and drain events until :meth:`stop` is called."""
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(FILE_INGESTED)
        _log.info("parser consumer subscribed channel=%s", FILE_INGESTED)
        try:
            async for message in self._iter_messages(pubsub):
                if self._stop_event.is_set():
                    break
                await self._handle(message)
        finally:
            await pubsub.unsubscribe(FILE_INGESTED)
            await pubsub.aclose()

    async def _iter_messages(self, pubsub: Any) -> AsyncIterator[dict[str, Any]]:
        while not self._stop_event.is_set():
            try:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — keep draining on transient errors
                _log.exception("redis pubsub get_message failed")
                await asyncio.sleep(1.0)
                continue
            if msg is None:
                continue
            yield msg

    async def _handle(self, message: dict[str, Any]) -> None:
        try:
            raw_data = message.get("data")
            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode("utf-8", errors="replace")
            if not isinstance(raw_data, str):
                _log.warning("dropping event with non-string data: %r", message)
                return
            payload: FileIngestedPayload = json.loads(raw_data)
        except (ValueError, TypeError):
            _log.exception("failed to decode file.ingested payload: %r", message)
            return

        sha = payload.get("sha256")
        user_id = payload.get("user_id")
        content_type = payload.get("content_type", "match-log")

        if not sha or user_id is None:
            _log.warning("ignoring event missing sha256/user_id: %r", payload)
            return
        if content_type != "match-log":
            _log.debug("skipping non-match-log event sha=%s ct=%s", sha, content_type)
            return

        await self.handle_event(sha, int(user_id))

    async def handle_event(self, sha256: str, user_id: int) -> ParsedMatch | None:
        """Test-friendly entry point — reads, parses, persists, publishes."""
        try:
            content = read_raw(sha256, self._raw_root, max_bytes=self._max_log_bytes)
        except RawFileNotFoundError:
            _log.warning("raw file missing for sha=%s; skipping", sha256)
            return None
        except RawFileTooLargeError:
            _log.warning("raw file exceeds size ceiling sha=%s; skipping", sha256)
            return None
        except OSError:
            _log.exception("failed to read raw file sha=%s", sha256)
            return None

        parsed = self._parser.parse(content)
        if not parsed.games and not parsed.winner and not parsed.format:
            # Nothing extractable — log and skip persistence so we don't
            # store an empty husk row.
            _log.warning("parsed log is empty sha=%s user_id=%s", sha256, user_id)
            return parsed

        async with self._sessionmaker() as session:
            try:
                match = await persist_match(session, parsed, sha256, user_id)
            except Exception:
                _log.exception("persist failed sha=%s user_id=%s", sha256, user_id)
                await session.rollback()
                return parsed

        out: MatchParsedPayload = {
            "match_id": str(match.id),
            "user_id": str(user_id),
            "game_count": parsed.game_count,
            "parsed_at": datetime.now(UTC).isoformat(),
        }
        try:
            await self._publisher.publish(MATCH_PARSED, dict(out))
        except Exception:  # noqa: BLE001 — best-effort
            _log.exception("match.parsed publish failed match_id=%s", match.id)

        _log.info(
            "match parsed match_id=%s sha=%s user_id=%s games=%s",
            match.id,
            sha256,
            user_id,
            parsed.game_count,
        )
        return parsed
