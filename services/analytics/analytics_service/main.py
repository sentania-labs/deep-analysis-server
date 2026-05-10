from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI

from analytics_service.archetypes import router as archetypes_router
from analytics_service.db import get_sessionmaker
from analytics_service.deps import AuthenticatedUser, require_admin
from analytics_service.scryfall_sync import run_sync, should_sync
from analytics_service.settings import get_settings
from analytics_service.stats import router as stats_router
from common.logging import configure_logging
from common.metrics import mount_metrics

SERVICE_NAME = "analytics"
configure_logging(SERVICE_NAME)

_log = logging.getLogger("analytics.main")

_scheduler_task: asyncio.Task[None] | None = None


def reset_scheduler() -> None:
    """Test hook."""
    global _scheduler_task
    _scheduler_task = None


async def _scheduler_loop() -> None:
    """Sleep-and-check loop driving periodic Scryfall syncs.

    Wakes up on the configured interval and asks ``should_sync`` —
    runs only when the cadence threshold has elapsed, so a manual
    admin sync resets the clock and we don't double-sync immediately
    after.
    """
    settings = get_settings()
    interval_seconds = settings.scryfall_sync_interval_days * 24 * 60 * 60
    sm = get_sessionmaker()
    while True:
        try:
            async with sm() as session:
                due = await should_sync(session)
            if due:
                await run_sync(sm)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never let scheduler crash kill the service
            _log.exception("scryfall scheduler iteration failed")
        await asyncio.sleep(interval_seconds)


async def _start_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task is not None:
        return
    _scheduler_task = asyncio.create_task(_scheduler_loop(), name="scryfall-scheduler")
    _log.info("scryfall scheduler task started")


async def _stop_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task is None:
        return
    _scheduler_task.cancel()
    try:
        await _scheduler_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 — surface but don't crash shutdown
        _log.exception("scryfall scheduler raised on shutdown")
    _scheduler_task = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        await _start_scheduler()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start scryfall scheduler; healthz remains available")
    try:
        yield
    finally:
        await _stop_scheduler()


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)
mount_metrics(app, SERVICE_NAME)
app.include_router(archetypes_router)
app.include_router(stats_router)


admin_router = APIRouter(prefix="/analytics/admin", tags=["admin"])


@admin_router.post("/sync-cards", status_code=202)
async def sync_cards(
    background_tasks: BackgroundTasks,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, str]:
    """Trigger a Scryfall card sync.

    Runs in the background — the bulk-data download + parse + upsert
    takes minutes; tying up an admin request that long is the wrong
    shape. Returns 202 immediately; progress shows up in service logs.
    """
    background_tasks.add_task(run_sync, get_sessionmaker())
    return {"status": "sync_started"}


app.include_router(admin_router)


@app.get("/healthz")
@app.get("/analytics/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
