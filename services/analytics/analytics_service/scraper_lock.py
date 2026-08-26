"""Per-scraper run lock (issue #127).

Why a database row and not an in-process flag
---------------------------------------------
Analytics is a plain FastAPI app that can be scaled to more than one
container. A module-level ``asyncio.Lock`` would silently stop holding
the moment a second replica exists: two processes, two locks, two
concurrent scrapes hammering someone else's website. The lock has to
live somewhere both processes can see, so it lives in Postgres, which
analytics already depends on and which already stores scraper health.

Why not a Postgres advisory lock
--------------------------------
``pg_try_advisory_lock`` has an attractive property (the lock dies with
the connection, so a SIGKILL releases it instantly), but it would mean
pinning one pooled connection for the whole multi-minute scrape, and it
carries no readable state: another process can see "locked" but not
*when the run started*, which is exactly what the admin UI and issue
#130 need. A heartbeat row gives us the lock and ``running_since`` as
one fact instead of two that can disagree.

Stale locks
-----------
A held lock is a row whose ``heartbeat_at`` was refreshed within
``STALE_AFTER_SECONDS``. While a scrape runs, a background task bumps
``heartbeat_at`` every ``HEARTBEAT_SECONDS``. Normal completion (and
any exception, via ``finally``) deletes the row.

If the container is SIGKILLed mid-scrape, nothing gets to run a
``finally``: the row stays behind with its last heartbeat. Nobody is
blocked forever, though. Once the heartbeat is older than
``STALE_AFTER_SECONDS`` the row is treated as dead: health reports
``is_running: false`` again, and the next trigger (manual or scheduled)
takes the row over rather than being refused. Worst case after a hard
kill is a ``STALE_AFTER_SECONDS`` window during which the UI still says
"running" and a manual trigger is refused with a 409.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_log = logging.getLogger("analytics.scraper_lock")

#: How often a running scrape refreshes ``heartbeat_at``.
HEARTBEAT_SECONDS = 30.0

#: A lock whose heartbeat is older than this is considered abandoned and
#: can be taken over. Six missed heartbeats: generous enough that a
#: slow HTML parse or a stalled event loop never steals a live lock.
STALE_AFTER_SECONDS = 180.0

TRIGGER_MANUAL = "manual"
TRIGGER_SCHEDULED = "scheduled"


class ScrapeAlreadyRunning(Exception):
    """Raised when a lock could not be acquired because a run is live.

    ``run`` is ``None`` in the rare case where the lock was contended but
    the losing caller could not read back the winner's row. Callers must
    report that as "running, start time unknown" rather than inventing
    one.
    """

    def __init__(self, scraper_name: str, run: ScraperRun | None = None) -> None:
        since = f" since {run.started_at}" if run is not None else ""
        super().__init__(f"{scraper_name} scrape already running{since}")
        self.scraper_name = scraper_name
        self.run = run


class ScrapeLeaseLost(Exception):
    """Raised when a running scrape lost its lock to another owner.

    Means the heartbeat could not be refreshed for longer than the
    staleness window (a stalled event loop, or database trouble), so the
    run was aborted mid-flight to keep the one-scrape-at-a-time
    guarantee.
    """

    def __init__(self, scraper_name: str, run: ScraperRun) -> None:
        super().__init__(f"{scraper_name} scrape aborted: run {run.run_id} lost its lock")
        self.scraper_name = scraper_name
        self.run = run


@dataclass(frozen=True)
class ScraperRun:
    """A row of ``analytics.scraper_runs`` plus its liveness verdict."""

    scraper_name: str
    run_id: str
    started_at: datetime
    heartbeat_at: datetime
    trigger: str
    owner: str | None
    is_live: bool


def owner_label() -> str:
    """Best-effort identity of this process, for operator diagnostics."""
    return f"{socket.gethostname()}:{os.getpid()}"


def is_live(heartbeat_at: datetime, now: datetime, stale_after_seconds: float) -> bool:
    """Pure staleness rule, shared by every store implementation."""
    return heartbeat_at > now - timedelta(seconds=stale_after_seconds)


def run_status_fields(run: ScraperRun | None) -> dict[str, Any]:
    """Serializable run state for scraper health payloads.

    Shape is deliberately flat so #130 (scraper diagnostics UI) can drop
    it straight into a template: which scraper (the enclosing health
    dict carries ``scraper_name``), when the active run started, and
    whether it is active at all. A stale row reports as not running.
    """
    if run is None or not run.is_live:
        return {
            "is_running": False,
            "running_since": None,
            "run_id": None,
            "run_trigger": None,
            "last_heartbeat_at": None,
        }
    return {
        "is_running": True,
        "running_since": run.started_at,
        "run_id": run.run_id,
        "run_trigger": run.trigger,
        "last_heartbeat_at": run.heartbeat_at,
    }


# --------------------------------------------------------------------------- #
# Stores
# --------------------------------------------------------------------------- #


class LockStore(Protocol):
    """Storage backend for the per-scraper run lock."""

    async def try_acquire(
        self, scraper_name: str, *, run_id: str, trigger: str, owner: str
    ) -> ScraperRun | None:
        """Take the lock, or return ``None`` if a live run holds it."""

    async def heartbeat(self, scraper_name: str, run_id: str) -> bool:
        """Refresh the heartbeat. False means we no longer hold the lock."""

    async def release(self, scraper_name: str, run_id: str) -> None:
        """Drop the lock if we still hold it."""

    async def read(self, scraper_name: str) -> ScraperRun | None:
        """Current lock row, with liveness resolved. ``None`` when idle."""


_ACQUIRE_SQL = text(
    """
    INSERT INTO analytics.scraper_runs
        (scraper_name, run_id, started_at, heartbeat_at, trigger, owner)
    VALUES (:scraper_name, :run_id, now(), now(), :trigger, :owner)
    ON CONFLICT (scraper_name) DO UPDATE SET
        run_id = EXCLUDED.run_id,
        started_at = now(),
        heartbeat_at = now(),
        trigger = EXCLUDED.trigger,
        owner = EXCLUDED.owner
      WHERE analytics.scraper_runs.heartbeat_at
            <= now() - make_interval(secs => :stale_after)
    RETURNING scraper_name, run_id, started_at, heartbeat_at, trigger, owner
    """
)

_HEARTBEAT_SQL = text(
    """
    UPDATE analytics.scraper_runs
       SET heartbeat_at = now()
     WHERE scraper_name = :scraper_name
       AND run_id = :run_id
    """
)

_RELEASE_SQL = text(
    """
    DELETE FROM analytics.scraper_runs
     WHERE scraper_name = :scraper_name
       AND run_id = :run_id
    """
)

_READ_SQL = text(
    """
    SELECT scraper_name, run_id, started_at, heartbeat_at, trigger, owner,
           (heartbeat_at > now() - make_interval(secs => :stale_after)) AS is_live
      FROM analytics.scraper_runs
     WHERE scraper_name = :scraper_name
    """
)


class PostgresLockStore:
    """The production store: one row per running scraper in Postgres.

    Every statement is a single atomic SQL round-trip, so two processes
    racing to acquire cannot both win: the loser's ``ON CONFLICT`` arm
    fails its ``WHERE`` clause and returns no row.
    """

    def __init__(
        self,
        sm: async_sessionmaker[AsyncSession],
        *,
        stale_after_seconds: float = STALE_AFTER_SECONDS,
    ) -> None:
        self._sm = sm
        self._stale_after = stale_after_seconds

    async def try_acquire(
        self, scraper_name: str, *, run_id: str, trigger: str, owner: str
    ) -> ScraperRun | None:
        async with self._sm() as session:
            row = (
                (
                    await session.execute(
                        _ACQUIRE_SQL,
                        {
                            "scraper_name": scraper_name,
                            "run_id": run_id,
                            "trigger": trigger,
                            "owner": owner,
                            "stale_after": self._stale_after,
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
            await session.commit()
        if row is None:
            return None
        return ScraperRun(**dict(row), is_live=True)

    async def heartbeat(self, scraper_name: str, run_id: str) -> bool:
        async with self._sm() as session:
            result = await session.execute(
                _HEARTBEAT_SQL, {"scraper_name": scraper_name, "run_id": run_id}
            )
            await session.commit()
        # CursorResult carries rowcount; the Result protocol does not.
        return bool(getattr(result, "rowcount", 0))

    async def release(self, scraper_name: str, run_id: str) -> None:
        async with self._sm() as session:
            await session.execute(_RELEASE_SQL, {"scraper_name": scraper_name, "run_id": run_id})
            await session.commit()

    async def read(self, scraper_name: str) -> ScraperRun | None:
        async with self._sm() as session:
            row = (
                (
                    await session.execute(
                        _READ_SQL,
                        {"scraper_name": scraper_name, "stale_after": self._stale_after},
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        data = dict(row)
        return ScraperRun(**{**data, "is_live": bool(data["is_live"])})


class InMemoryLockStore:
    """Single-process store used by unit tests.

    Mirrors ``PostgresLockStore`` semantics exactly: acquire succeeds
    only when there is no row or the row is stale, heartbeat and release
    are guarded by ``run_id``, and reads resolve liveness against the
    same staleness rule. The clock is injectable so a test can age a
    lock without sleeping.
    """

    def __init__(
        self,
        *,
        stale_after_seconds: float = STALE_AFTER_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._rows: dict[str, ScraperRun] = {}
        self._stale_after = stale_after_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    async def try_acquire(
        self, scraper_name: str, *, run_id: str, trigger: str, owner: str
    ) -> ScraperRun | None:
        now = self._clock()
        existing = self._rows.get(scraper_name)
        if existing is not None and is_live(existing.heartbeat_at, now, self._stale_after):
            return None
        run = ScraperRun(
            scraper_name=scraper_name,
            run_id=run_id,
            started_at=now,
            heartbeat_at=now,
            trigger=trigger,
            owner=owner,
            is_live=True,
        )
        self._rows[scraper_name] = run
        return run

    async def heartbeat(self, scraper_name: str, run_id: str) -> bool:
        existing = self._rows.get(scraper_name)
        if existing is None or existing.run_id != run_id:
            return False
        self._rows[scraper_name] = ScraperRun(
            scraper_name=existing.scraper_name,
            run_id=existing.run_id,
            started_at=existing.started_at,
            heartbeat_at=self._clock(),
            trigger=existing.trigger,
            owner=existing.owner,
            is_live=True,
        )
        return True

    async def release(self, scraper_name: str, run_id: str) -> None:
        existing = self._rows.get(scraper_name)
        if existing is not None and existing.run_id == run_id:
            del self._rows[scraper_name]

    async def read(self, scraper_name: str) -> ScraperRun | None:
        existing = self._rows.get(scraper_name)
        if existing is None:
            return None
        live = is_live(existing.heartbeat_at, self._clock(), self._stale_after)
        return ScraperRun(
            scraper_name=existing.scraper_name,
            run_id=existing.run_id,
            started_at=existing.started_at,
            heartbeat_at=existing.heartbeat_at,
            trigger=existing.trigger,
            owner=existing.owner,
            is_live=live,
        )


# --------------------------------------------------------------------------- #
# Store resolution
# --------------------------------------------------------------------------- #

_store: LockStore | None = None


def get_store() -> LockStore:
    """Process-wide lock store. Lazily bound to the analytics engine."""
    global _store
    if _store is None:
        from analytics_service.db import get_sessionmaker

        _store = PostgresLockStore(get_sessionmaker())
    return _store


def set_store(store: LockStore | None) -> None:
    """Swap the store (tests) or reset it to the Postgres default."""
    global _store
    _store = store


# --------------------------------------------------------------------------- #
# Acquire / hold / run
# --------------------------------------------------------------------------- #


async def acquire(
    scraper_name: str,
    *,
    trigger: str,
    store: LockStore | None = None,
) -> ScraperRun:
    """Take the run lock or raise ``ScrapeAlreadyRunning``."""
    st = store or get_store()
    run = await st.try_acquire(
        scraper_name,
        run_id=str(uuid.uuid4()),
        trigger=trigger,
        owner=owner_label(),
    )
    if run is not None:
        return run

    current = await st.read(scraper_name)
    if current is not None and current.is_live:
        raise ScrapeAlreadyRunning(scraper_name, current)

    # The holder released between our attempt and this read. The caller
    # asked for a run and nothing is running now, so try once more.
    run = await st.try_acquire(
        scraper_name,
        run_id=str(uuid.uuid4()),
        trigger=trigger,
        owner=owner_label(),
    )
    if run is not None:
        return run
    raise ScrapeAlreadyRunning(scraper_name, await st.read(scraper_name))


async def get_run(scraper_name: str, *, store: LockStore | None = None) -> ScraperRun | None:
    """Read the current run row (``None`` when no row exists)."""
    return await (store or get_store()).read(scraper_name)


async def _heartbeat_loop(
    store: LockStore, run: ScraperRun, interval: float, lost: asyncio.Event
) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            held = await store.heartbeat(run.scraper_name, run.run_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (a failed heartbeat must not kill the scrape)
            _log.warning(
                "scraper lock heartbeat failed",
                extra={"scraper_name": run.scraper_name, "run_id": run.run_id},
                exc_info=True,
            )
            continue
        if not held:
            # Our row is gone or belongs to someone else: the staleness
            # window elapsed for us and somebody legitimately took over.
            # Do not steal it back, and do not keep scraping alongside the
            # new owner: signal the holder so it aborts the run.
            _log.warning(
                "scraper lock lost; another process took it over",
                extra={"scraper_name": run.scraper_name, "run_id": run.run_id},
            )
            lost.set()
            return


@asynccontextmanager
async def held(
    run: ScraperRun,
    *,
    store: LockStore | None = None,
    heartbeat_seconds: float = HEARTBEAT_SECONDS,
    lost: asyncio.Event | None = None,
) -> AsyncIterator[ScraperRun]:
    """Hold an acquired lock: heartbeat while inside, release on exit.

    Release happens in ``finally``, so a scrape that raises frees the
    lock just like one that returns. ``lost`` is set if the heartbeat
    finds the row taken over, so the caller can abort the work rather
    than run on unlocked next to the new owner.
    """
    st = store or get_store()
    beat = asyncio.create_task(_heartbeat_loop(st, run, heartbeat_seconds, lost or asyncio.Event()))
    try:
        yield run
    finally:
        beat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await beat
        try:
            await st.release(run.scraper_name, run.run_id)
        except Exception:  # noqa: BLE001  (a failed release only leaves a stale lock)
            _log.warning(
                "scraper lock release failed; lock will expire as stale",
                extra={"scraper_name": run.scraper_name, "run_id": run.run_id},
                exc_info=True,
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
    """Run ``runner`` while holding the scraper's lock.

    Pass ``run`` when the lock was already acquired by the caller (the
    admin endpoints acquire before returning 202 so they can answer 409
    on the spot). Otherwise the lock is acquired here and
    ``ScrapeAlreadyRunning`` propagates to the caller.
    """
    st = store or get_store()
    acquired = run if run is not None else await acquire(scraper_name, trigger=trigger, store=st)
    lost = asyncio.Event()
    async with held(acquired, store=st, heartbeat_seconds=heartbeat_seconds, lost=lost):
        # ensure_future, not create_task: runner is typed Awaitable[T].
        work: asyncio.Task[T] = asyncio.ensure_future(runner())
        watch = asyncio.create_task(lost.wait())
        try:
            await asyncio.wait({work, watch}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            watch.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watch
        if work.done():
            return work.result()
        # The lease is gone and somebody else owns the scraper now.
        # Stop fetching immediately: two concurrent scrapes is the exact
        # thing this lock exists to prevent.
        work.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await work
        raise ScrapeLeaseLost(scraper_name, acquired)
