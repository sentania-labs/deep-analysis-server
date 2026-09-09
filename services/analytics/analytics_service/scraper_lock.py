"""Per-scraper run lock (issue #127), bound to ``analytics.scraper_runs``.

The mechanism itself now lives in ``common.job_lock`` (issue #161
needed the same guarantee for the ingest raw-archive backfill, and
#155 needs it for the analytics loops that are still unprotected). This
module is the analytics binding: it owns the table name, the
process-wide store, and the thin wrappers that default ``store`` to it
so existing call sites read unchanged.

The table keeps its original ``scraper_name`` primary key rather than
being renamed to ``job_name``: renaming a live table to match a
refactor is churn with a migration attached and no operator benefit.
``PostgresJobLockStore`` takes the column name for exactly this reason.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager

from common.job_lock import (
    HEARTBEAT_SECONDS,
    STALE_AFTER_SECONDS,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    InMemoryJobLockStore,
    JobAlreadyRunning,
    JobLeaseLost,
    JobRun,
    LockStore,
    PostgresJobLockStore,
    is_live,
    owner_label,
    run_status_fields,
)
from common.job_lock import acquire as _acquire
from common.job_lock import get_run as _get_run
from common.job_lock import held as _held
from common.job_lock import run_locked as _run_locked

#: Where the analytics lock rows live. Predates the generalisation, so
#: the primary key is ``scraper_name`` and not ``job_name``.
SCRAPER_RUNS_TABLE = "analytics.scraper_runs"
SCRAPER_NAME_COLUMN = "scraper_name"

# Names re-exported under their original analytics spellings so the
# service and its tests keep reading in scraper vocabulary.
ScraperRun = JobRun
ScrapeAlreadyRunning = JobAlreadyRunning
ScrapeLeaseLost = JobLeaseLost
InMemoryLockStore = InMemoryJobLockStore

__all__ = [
    "HEARTBEAT_SECONDS",
    "SCRAPER_NAME_COLUMN",
    "SCRAPER_RUNS_TABLE",
    "STALE_AFTER_SECONDS",
    "TRIGGER_MANUAL",
    "TRIGGER_SCHEDULED",
    "InMemoryLockStore",
    "LockStore",
    "ScrapeAlreadyRunning",
    "ScrapeLeaseLost",
    "ScraperRun",
    "acquire",
    "get_run",
    "get_store",
    "held",
    "is_live",
    "owner_label",
    "run_locked",
    "run_status_fields",
    "set_store",
]

_store: LockStore | None = None


def get_store() -> LockStore:
    """Process-wide lock store. Lazily bound to the analytics engine."""
    global _store
    if _store is None:
        from analytics_service.db import get_sessionmaker

        _store = PostgresJobLockStore(
            get_sessionmaker(),
            table=SCRAPER_RUNS_TABLE,
            name_column=SCRAPER_NAME_COLUMN,
        )
    return _store


def set_store(store: LockStore | None) -> None:
    """Swap the store (tests) or reset it to the Postgres default."""
    global _store
    _store = store


async def acquire(scraper_name: str, *, trigger: str, store: LockStore | None = None) -> ScraperRun:
    """Take the scraper's run lock or raise ``ScrapeAlreadyRunning``."""
    return await _acquire(scraper_name, trigger=trigger, store=store or get_store())


async def get_run(scraper_name: str, *, store: LockStore | None = None) -> ScraperRun | None:
    """Read the current run row (``None`` when no row exists)."""
    return await _get_run(scraper_name, store=store or get_store())


def held(
    run: ScraperRun,
    *,
    store: LockStore | None = None,
    heartbeat_seconds: float = HEARTBEAT_SECONDS,
    lost: asyncio.Event | None = None,
) -> AbstractAsyncContextManager[ScraperRun]:
    """Hold an acquired lock; see ``common.job_lock.held``."""
    return _held(
        run,
        store=store or get_store(),
        heartbeat_seconds=heartbeat_seconds,
        lost=lost,
    )


async def run_locked[T](
    scraper_name: str,
    runner: Callable[[], Awaitable[T]],
    *,
    trigger: str,
    store: LockStore | None = None,
    run: ScraperRun | None = None,
    heartbeat_seconds: float = HEARTBEAT_SECONDS,
) -> T:
    """Run ``runner`` while holding the scraper's lock."""
    return await _run_locked(
        scraper_name,
        runner,
        trigger=trigger,
        store=store or get_store(),
        run=run,
        heartbeat_seconds=heartbeat_seconds,
    )
