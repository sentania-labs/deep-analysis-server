"""Parser service entrypoint.

The parser is primarily a Redis pub/sub worker — but it also runs a
small FastAPI app so the docker healthcheck and Prometheus scraper
have something to talk to. The consumer task is started on app
startup and stopped on shutdown.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from common.logging import configure_logging
from common.metrics import mount_metrics
from common.redis_client import EventPublisher, get_redis
from parser_service import models as _models  # noqa: F401 — load Base.metadata
from parser_service.backfill import backfill_loop
from parser_service.consumer import ParserConsumer
from parser_service.db import get_sessionmaker
from parser_service.parsing import LogParser
from parser_service.settings import get_settings

SERVICE_NAME = "parser"
configure_logging(SERVICE_NAME)

_log = logging.getLogger("parser.main")

_consumer: ParserConsumer | None = None
_consumer_task: asyncio.Task[None] | None = None
_backfill_task: asyncio.Task[None] | None = None
_backfill_stop: asyncio.Event | None = None


def reset_consumer() -> None:
    """Test hook."""
    global _consumer, _consumer_task, _backfill_task, _backfill_stop
    _consumer = None
    _consumer_task = None
    _backfill_task = None
    _backfill_stop = None


async def _start_consumer() -> None:
    global _consumer, _consumer_task, _backfill_task, _backfill_stop
    settings = get_settings()
    client = await get_redis(settings.redis_url)
    sm = get_sessionmaker()
    _consumer = ParserConsumer(
        redis_client=client,
        sessionmaker=sm,
        raw_root=settings.parser_raw_path,
        parser=LogParser(),
        publisher=EventPublisher(client),
        max_log_bytes=settings.parser_max_log_bytes,
    )
    _consumer_task = asyncio.create_task(_consumer.run(), name="parser-consumer")
    _log.info("parser consumer task started")

    _backfill_stop = asyncio.Event()
    _backfill_task = asyncio.create_task(
        backfill_loop(sm, _consumer, settings.backfill_interval_seconds, _backfill_stop),
        name="parser-backfill",
    )


async def _stop_consumer() -> None:
    global _consumer, _consumer_task, _backfill_task, _backfill_stop
    if _backfill_stop is not None:
        _backfill_stop.set()
    if _backfill_task is not None:
        try:
            await asyncio.wait_for(_backfill_task, timeout=5.0)
        except TimeoutError:
            _backfill_task.cancel()
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001
            _log.exception("backfill task raised on shutdown")
    _backfill_task = None
    _backfill_stop = None

    if _consumer is not None:
        _consumer.stop()
    if _consumer_task is not None:
        try:
            await asyncio.wait_for(_consumer_task, timeout=5.0)
        except TimeoutError:
            _consumer_task.cancel()
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 — surface but don't crash shutdown
            _log.exception("consumer task raised on shutdown")
    _consumer = None
    _consumer_task = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        await _start_consumer()
    except Exception:  # noqa: BLE001 — healthz still serves even if redis is down
        _log.exception("failed to start parser consumer; healthz remains available")
    try:
        yield
    finally:
        await _stop_consumer()


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)
mount_metrics(app, SERVICE_NAME)

from parser_service.reingest import router as _reingest_router  # noqa: E402

app.include_router(_reingest_router)


@app.get("/healthz")
@app.get("/parser/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
