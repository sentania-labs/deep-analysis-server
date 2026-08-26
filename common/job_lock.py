"""Named background-job run lock, shared by every service (issues #127, #155, #161).

This is the generalisation of what analytics grew for its scrapers in
#127. Nothing about a heartbeat row is scraper-specific, and two other
places now need exactly the same guarantee: the analytics loops that
are still unprotected (#155) and the ingest raw-archive backfill that
must not run twice when a second ingest replica starts (#161). So the
mechanism lives here and each service binds it to its own table.

Why a database row and not an in-process flag
---------------------------------------------
Services are plain FastAPI apps that can be scaled to more than one
container. A module-level ``asyncio.Lock`` would silently stop holding
the moment a second replica exists: two processes, two locks, two
concurrent runs. The lock has to live somewhere both processes can see,
so it lives in Postgres, which every service already depends on.

Why not a Postgres advisory lock
--------------------------------
``pg_try_advisory_lock`` has an attractive property (the lock dies with
the connection, so a SIGKILL releases it instantly), but it would mean
pinning one pooled connection for the whole multi-minute job, and it
carries no readable state: another process can see "locked" but not
*when the run started*, which is exactly what the admin UI needs. A
heartbeat row gives us the lock and ``running_since`` as one fact
instead of two that can disagree.

Stale locks
-----------
A held lock is a row whose ``heartbeat_at`` was refreshed within
``STALE_AFTER_SECONDS``. While a job runs, a background task bumps
``heartbeat_at`` every ``HEARTBEAT_SECONDS``. Normal completion (and
any exception, via ``finally``) deletes the row.

If the container is SIGKILLed mid-run, nothing gets to run a
``finally``: the row stays behind with its last heartbeat. Nobody is
blocked forever, though. Once the heartbeat is older than
``STALE_AFTER_SECONDS`` the row is treated as dead: status reports
``is_running: false`` again, and the next trigger takes the row over
rather than being refused. Worst case after a hard kill is a
``STALE_AFTER_SECONDS`` window during which the UI still says "running"
and a manual trigger is refused with a 409.

Binding it to a table
---------------------
``PostgresJobLockStore`` takes the qualified table name and the name of
its primary-key column, because analytics already shipped
``analytics.scraper_runs(scraper_name, ...)`` and renaming a live table
is not worth it. Both identifiers are validated against a strict
pattern before they are interpolated into SQL: they come from module
constants, never from a request, and the guard keeps it that way.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import socket
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_log = logging.getLogger("common.job_lock")

#: How often a running job refreshes ``heartbeat_at``.
HEARTBEAT_SECONDS = 30.0

#: A lock whose heartbeat is older than this is considered abandoned and
#: can be taken over. Six missed heartbeats: generous enough that a slow
#: iteration or a stalled event loop never steals a live lock.
STALE_AFTER_SECONDS = 180.0

TRIGGER_MANUAL = "manual"
TRIGGER_SCHEDULED = "scheduled"
#: A job the service started on its own at boot, with no operator input.
TRIGGER_STARTUP = "startup"

# Table and column names are interpolated into SQL, so they are held to
# a bare-identifier shape. Nothing outside this module's callers should
# ever be able to reach these values, and this makes that structural.
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_QUALIFIED = re.compile(r"^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$")


class JobAlreadyRunning(Exception):
    """Raised when a lock could not be acquired because a run is live.

    ``run`` is ``None`` in the rare case where the lock was contended but
    the losing caller could not read back the winner's row. Callers must
    report that as "running, start time unknown" rather than inventing
    one.
    """

    def __init__(self, job_name: str, run: JobRun | None = None) -> None:
        since = f" since {run.started_at}" if run is not None else ""
        super().__init__(f"{job_name} already running{since}")
        self.job_name = job_name
        self.run = run


class JobLeaseLost(Exception):
    """Raised when a running job lost its lock to another owner.

    Means the heartbeat could not be refreshed for longer than the
    staleness window (a stalled event loop, or database trouble), so the
    run was aborted mid-flight to keep the one-at-a-time guarantee.
    """

    def __init__(self, job_name: str, run: JobRun) -> None:
        super().__init__(f"{job_name} aborted: run {run.run_id} lost its lock")
        self.job_name = job_name
        self.run = run


@dataclass(frozen=True)
class JobRun:
    """A lock row plus its liveness verdict."""

    job_name: str
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


def run_status_fields(run: JobRun | None) -> dict[str, Any]:
    """Serializable run state for status payloads.

    Shape is deliberately flat so a template can drop it straight in:
    when the active run started, and whether it is active at all. A
    stale row reports as not running.
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
    """Storage backend for the named job run lock."""

    async def try_acquire(
        self, job_name: str, *, run_id: str, trigger: str, owner: str
    ) -> JobRun | None:
        """Take the lock, or return ``None`` if a live run holds it."""

    async def heartbeat(self, job_name: str, run_id: str) -> bool:
        """Refresh the heartbeat. False means we no longer hold the lock."""

    async def release(self, job_name: str, run_id: str) -> None:
        """Drop the lock if we still hold it."""

    async def read(self, job_name: str) -> JobRun | None:
        """Current lock row, with liveness resolved. ``None`` when idle."""


class PostgresJobLockStore:
    """The production store: one row per running job in Postgres.

    Every statement is a single atomic SQL round-trip, so two processes
    racing to acquire cannot both win: the loser's ``ON CONFLICT`` arm
    fails its ``WHERE`` clause and returns no row.
    """

    def __init__(
        self,
        sm: async_sessionmaker[AsyncSession],
        *,
        table: str,
        name_column: str = "job_name",
        stale_after_seconds: float = STALE_AFTER_SECONDS,
    ) -> None:
        if not _QUALIFIED.match(table):
            raise ValueError(f"table must be schema-qualified and bare: {table!r}")
        if not _IDENT.match(name_column):
            raise ValueError(f"name_column must be a bare identifier: {name_column!r}")
        self._sm = sm
        self._table = table
        self._col = name_column
        self._stale_after = stale_after_seconds
        self._acquire_sql = text(
            f"""
            INSERT INTO {table}
                ({name_column}, run_id, started_at, heartbeat_at, trigger, owner)
            VALUES (:job_name, :run_id, now(), now(), :trigger, :owner)
            ON CONFLICT ({name_column}) DO UPDATE SET
                run_id = EXCLUDED.run_id,
                started_at = now(),
                heartbeat_at = now(),
                trigger = EXCLUDED.trigger,
                owner = EXCLUDED.owner
              WHERE {table}.heartbeat_at
                    <= now() - make_interval(secs => :stale_after)
            RETURNING {name_column} AS job_name, run_id, started_at,
                      heartbeat_at, trigger, owner
            """
        )
        self._heartbeat_sql = text(
            f"UPDATE {table} SET heartbeat_at = now() "
            f"WHERE {name_column} = :job_name AND run_id = :run_id"
        )
        self._release_sql = text(
            f"DELETE FROM {table} WHERE {name_column} = :job_name AND run_id = :run_id"
        )
        self._read_sql = text(
            f"""
            SELECT {name_column} AS job_name, run_id, started_at, heartbeat_at,
                   trigger, owner,
                   (heartbeat_at > now() - make_interval(secs => :stale_after)) AS is_live
              FROM {table}
             WHERE {name_column} = :job_name
            """
        )

    async def try_acquire(
        self, job_name: str, *, run_id: str, trigger: str, owner: str
    ) -> JobRun | None:
        async with self._sm() as session:
            row = (
                (
                    await session.execute(
                        self._acquire_sql,
                        {
                            "job_name": job_name,
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
        return JobRun(**dict(row), is_live=True)

    async def heartbeat(self, job_name: str, run_id: str) -> bool:
        async with self._sm() as session:
            result = await session.execute(
                self._heartbeat_sql, {"job_name": job_name, "run_id": run_id}
            )
            await session.commit()
        # CursorResult carries rowcount; the Result protocol does not.
        return bool(getattr(result, "rowcount", 0))

    async def release(self, job_name: str, run_id: str) -> None:
        async with self._sm() as session:
            await session.execute(self._release_sql, {"job_name": job_name, "run_id": run_id})
            await session.commit()

    async def read(self, job_name: str) -> JobRun | None:
        async with self._sm() as session:
            row = (
                (
                    await session.execute(
                        self._read_sql,
                        {"job_name": job_name, "stale_after": self._stale_after},
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            return None
        data = dict(row)
        return JobRun(**{**data, "is_live": bool(data["is_live"])})


class InMemoryJobLockStore:
    """Single-process store used by unit tests.

    Mirrors ``PostgresJobLockStore`` semantics exactly: acquire succeeds
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
        self._rows: dict[str, JobRun] = {}
        self._stale_after = stale_after_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    async def try_acquire(
        self, job_name: str, *, run_id: str, trigger: str, owner: str
    ) -> JobRun | None:
        now = self._clock()
        existing = self._rows.get(job_name)
        if existing is not None and is_live(existing.heartbeat_at, now, self._stale_after):
            return None
        run = JobRun(
            job_name=job_name,
            run_id=run_id,
            started_at=now,
            heartbeat_at=now,
            trigger=trigger,
            owner=owner,
            is_live=True,
        )
        self._rows[job_name] = run
        return run

    async def heartbeat(self, job_name: str, run_id: str) -> bool:
        existing = self._rows.get(job_name)
        if existing is None or existing.run_id != run_id:
            return False
        self._rows[job_name] = JobRun(
            job_name=existing.job_name,
            run_id=existing.run_id,
            started_at=existing.started_at,
            heartbeat_at=self._clock(),
            trigger=existing.trigger,
            owner=existing.owner,
            is_live=True,
        )
        return True

    async def release(self, job_name: str, run_id: str) -> None:
        existing = self._rows.get(job_name)
        if existing is not None and existing.run_id == run_id:
            del self._rows[job_name]

    async def read(self, job_name: str) -> JobRun | None:
        existing = self._rows.get(job_name)
        if existing is None:
            return None
        live = is_live(existing.heartbeat_at, self._clock(), self._stale_after)
        return JobRun(
            job_name=existing.job_name,
            run_id=existing.run_id,
            started_at=existing.started_at,
            heartbeat_at=existing.heartbeat_at,
            trigger=existing.trigger,
            owner=existing.owner,
            is_live=live,
        )


# --------------------------------------------------------------------------- #
# Acquire / hold / run
# --------------------------------------------------------------------------- #


async def acquire(job_name: str, *, trigger: str, store: LockStore) -> JobRun:
    """Take the run lock or raise ``JobAlreadyRunning``."""
    run = await store.try_acquire(
        job_name, run_id=str(uuid.uuid4()), trigger=trigger, owner=owner_label()
    )
    if run is not None:
        return run

    current = await store.read(job_name)
    if current is not None and current.is_live:
        raise JobAlreadyRunning(job_name, current)

    # The holder released between our attempt and this read. The caller
    # asked for a run and nothing is running now, so try once more.
    run = await store.try_acquire(
        job_name, run_id=str(uuid.uuid4()), trigger=trigger, owner=owner_label()
    )
    if run is not None:
        return run
    raise JobAlreadyRunning(job_name, await store.read(job_name))


async def get_run(job_name: str, *, store: LockStore) -> JobRun | None:
    """Read the current run row (``None`` when no row exists)."""
    return await store.read(job_name)


async def _heartbeat_loop(
    store: LockStore, run: JobRun, interval: float, lost: asyncio.Event
) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            held_still = await store.heartbeat(run.job_name, run.run_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (a failed heartbeat must not kill the job)
            _log.warning(
                "job lock heartbeat failed",
                extra={"job_name": run.job_name, "run_id": run.run_id},
                exc_info=True,
            )
            continue
        if not held_still:
            # Our row is gone or belongs to someone else: the staleness
            # window elapsed for us and somebody legitimately took over.
            # Do not steal it back, and do not keep working alongside the
            # new owner: signal the holder so it aborts the run.
            _log.warning(
                "job lock lost; another process took it over",
                extra={"job_name": run.job_name, "run_id": run.run_id},
            )
            lost.set()
            return


@asynccontextmanager
async def held(
    run: JobRun,
    *,
    store: LockStore,
    heartbeat_seconds: float = HEARTBEAT_SECONDS,
    lost: asyncio.Event | None = None,
) -> AsyncIterator[JobRun]:
    """Hold an acquired lock: heartbeat while inside, release on exit.

    Release happens in ``finally``, so a job that raises frees the lock
    just like one that returns. ``lost`` is set if the heartbeat finds
    the row taken over, so the caller can abort the work rather than run
    on unlocked next to the new owner.
    """
    beat = asyncio.create_task(
        _heartbeat_loop(store, run, heartbeat_seconds, lost or asyncio.Event())
    )
    try:
        yield run
    finally:
        beat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await beat
        try:
            await store.release(run.job_name, run.run_id)
        except Exception:  # noqa: BLE001  (a failed release only leaves a stale lock)
            _log.warning(
                "job lock release failed; lock will expire as stale",
                extra={"job_name": run.job_name, "run_id": run.run_id},
                exc_info=True,
            )


async def run_locked[T](
    job_name: str,
    runner: Callable[[], Awaitable[T]],
    *,
    trigger: str,
    store: LockStore,
    run: JobRun | None = None,
    heartbeat_seconds: float = HEARTBEAT_SECONDS,
) -> T:
    """Run ``runner`` while holding the job's lock.

    Pass ``run`` when the lock was already acquired by the caller (admin
    endpoints acquire before returning 202 so they can answer 409 on the
    spot). Otherwise the lock is acquired here and ``JobAlreadyRunning``
    propagates to the caller.
    """
    acquired = run if run is not None else await acquire(job_name, trigger=trigger, store=store)
    lost = asyncio.Event()
    async with held(acquired, store=store, heartbeat_seconds=heartbeat_seconds, lost=lost):
        # ensure_future, not create_task: runner is typed Awaitable[T].
        work: asyncio.Task[T] = asyncio.ensure_future(runner())
        watch = asyncio.create_task(lost.wait())
        try:
            await asyncio.wait({work, watch}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            # We were cancelled from outside (a SIGTERM reaching the
            # lifespan, say). asyncio.wait does NOT cancel what it was
            # waiting on, so without this the runner keeps going while
            # `held` releases the lock on the way out: another replica
            # could acquire and run concurrently with a job that is
            # still writing. Stop the work before the lock is dropped.
            work.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await work
            raise
        finally:
            watch.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watch
        if work.done():
            return work.result()
        # The lease is gone and somebody else owns the job now. Stop
        # immediately: two concurrent runs is the exact thing this lock
        # exists to prevent.
        work.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await work
        raise JobLeaseLost(job_name, acquired)
