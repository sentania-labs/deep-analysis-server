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
from fastapi.responses import JSONResponse

from common.logging import configure_logging
from common.metrics import start_metrics_server
from common.redis_client import EventPublisher, get_redis
from common.storage import ObjectStore, get_object_store, reset_object_store
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


def get_store() -> ObjectStore:
    """The raw archive. Built once per process from settings."""
    return get_object_store(get_settings().s3_config())


def reset_store() -> None:
    """Test hook."""
    reset_object_store()


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
        store=get_store(),
        key_prefix=settings.s3_key_prefix,
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
    start_metrics_server(SERVICE_NAME, get_settings().metrics_port)
    try:
        await _start_consumer()
    except Exception:  # noqa: BLE001 — healthz still serves even if redis is down
        _log.exception("failed to start parser consumer; healthz remains available")
    try:
        yield
    finally:
        await _stop_consumer()


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)

from parser_service.reparse import router as _reparse_router  # noqa: E402

app.include_router(_reparse_router)


@app.get("/healthz")
@app.get("/parser/healthz")
async def healthz() -> JSONResponse:
    from common.health import check_db, check_object_store, check_redis, evaluate

    redis_client = await get_redis(get_settings().redis_url)
    report = await evaluate(
        [
            check_db(get_sessionmaker()),
            check_redis(redis_client),
            # A parser that cannot reach the archive parses nothing.
            # Say so here rather than looking healthy while stuck.
            check_object_store(get_store()),
        ]
    )
    return JSONResponse(
        content=report.to_dict(SERVICE_NAME),
        status_code=report.http_status,
    )
