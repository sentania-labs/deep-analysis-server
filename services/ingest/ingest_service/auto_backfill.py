"""Run the legacy-archive migration by itself, after ingest is serving (issue #161).

#135 moved the raw archive into object storage and shipped the
migration as a hand-run one-shot job. Everything that re-reads a raw
log (force-reparse, the parser backfill scan, admin re-ingest) fails
with ``RawFileNotFoundError`` until somebody remembers to run it. This
module closes that gap: after a deploy the migration happens on its
own, and an operator only intervenes if they want to stop it.

What this module is not: it is not a second migration. The moving of
bytes is still ``backfill_s3.run_backfill``, unchanged in what it does
and still never deleting anything from the source. This is the
*scheduling* around it.

Four properties it exists to guarantee
--------------------------------------
**It does not delay readiness.** The migration runs in a task created
during lifespan startup but never awaited there. Creating a task does
not execute its body, so the lifespan returns immediately: healthz
answers and uploads are served while the migration is still moving
5,000 objects. A migration inside container start would make every
deploy look like a hang.

**Exactly one replica migrates.** Two ingest containers coming up
together would otherwise both walk the whole archive. The run is
wrapped in the shared Postgres job lock (``common.job_lock``, the
mechanism analytics grew for its scrapers in #127), so the loser skips
and waits rather than duplicating the work.

**It is resumable.** A container killed mid-migration loses nothing:
keys are content-addressed and the run re-derives its work list from
the database every time, so the next start re-checks what is already in
the store (one HEAD each) and moves only what is missing. Nothing is
double-written and nothing is corrupted. The abandoned lock row expires
as stale after ``STALE_AFTER_SECONDS``, and the restarted process
retries on an interval until it can take it over.

**A finished migration costs nothing.** ``ingest.backfill_state`` holds
the verdict durably. Once a run verifies every row present in the
store, the row reads ``complete`` and every later boot stops at that
single primary-key read: no directory walk, no row scan, no HEAD
storm. On a fresh install with no legacy archive the same thing happens
via an even cheaper route (``SELECT 1 FROM game_log_files LIMIT 1``).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prometheus_client import Gauge
from sqlalchemy import text

from common.job_lock import (
    TRIGGER_MANUAL,
    TRIGGER_STARTUP,
    JobAlreadyRunning,
    JobLeaseLost,
    JobRun,
    LockStore,
    run_locked,
    run_status_fields,
)
from common.storage import ObjectStore
from ingest_service.backfill_s3 import BackfillCounts, run_backfill

_log = logging.getLogger("ingest.auto_backfill")

#: The one job this module runs. Also the primary key of both the lock
#: row and the state row, so the two always refer to the same thing.
JOB_NAME = "raw_archive_s3"

#: Terminal states: an automatic run stops here and does not retry.
#: ``stalled`` is terminal for the automatic path only; a manual
#: trigger still overrides it, which is the point of the distinction.
_AUTO_TERMINAL = {"complete", "stalled"}

#: How long the startup task waits before re-trying a lock another
#: replica (or its own killed predecessor) still holds.
RETRY_SECONDS = 60.0

#: How many times the startup task will actually run the migration
#: before giving up and leaving it to an operator. Bounded so two
#: replicas cannot ping-pong retries forever on a permanent failure.
MAX_AUTO_ATTEMPTS = 5

#: How many times, per allowed attempt, the startup task will wait out a
#: lock somebody else holds before giving up on it entirely.
_MAX_WAITS_PER_ATTEMPT = 4


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
#
# Served on the existing metrics port (DA_METRICS_PORT), not the app
# port. The point is that "how far along is it" never requires reading
# container logs.

_G_EXPECTED = Gauge(
    "ingest_raw_backfill_expected",
    "Rows in ingest.game_log_files the raw-archive migration must account for",
)
_G_PROCESSED = Gauge(
    "ingest_raw_backfill_processed",
    "Rows the current or last raw-archive migration pass has accounted for",
)
_G_REMAINING = Gauge(
    "ingest_raw_backfill_remaining",
    "Rows the current or last raw-archive migration pass has not accounted for yet",
)
_G_UPLOADED = Gauge(
    "ingest_raw_backfill_uploaded",
    "Objects moved from the legacy archive into the object store in this pass",
)
_G_MISSING_SOURCE = Gauge(
    "ingest_raw_backfill_missing_source",
    "Rows with no file on the legacy archive to migrate",
)
_G_FAILED = Gauge(
    "ingest_raw_backfill_failed",
    "Rows whose migration failed in this pass",
)
_G_VERIFY_ERRORS = Gauge(
    "ingest_raw_backfill_verify_errors",
    "Rows the verify pass could not check because the store was unreachable",
)
_G_RUNNING = Gauge(
    "ingest_raw_backfill_running",
    "1 while this process is migrating the legacy raw archive, else 0",
)
_G_COMPLETE = Gauge(
    "ingest_raw_backfill_complete",
    "1 once every row is verified present in the object store, else 0",
)
_G_SOURCE_AVAILABLE = Gauge(
    "ingest_raw_backfill_source_available",
    "1 when the legacy archive path is mounted and holds files, else 0",
)


def _publish_metrics(state: BackfillState) -> None:
    """Publish the shared, durable facts.

    ``_G_RUNNING`` is deliberately NOT set here. Every replica can read
    this row, but only one of them is doing the work, and a gauge that
    says "running" on a process that is running nothing is a lie an
    operator would act on. It is set by the process that actually holds
    the run, in ``run_once``.
    """
    _G_EXPECTED.set(state.expected)
    _G_PROCESSED.set(state.processed)
    _G_REMAINING.set(state.remaining)
    _G_UPLOADED.set(state.uploaded)
    _G_MISSING_SOURCE.set(state.missing_source)
    _G_FAILED.set(state.failed)
    _G_VERIFY_ERRORS.set(state.verify_errors)
    _G_COMPLETE.set(1 if state.status == "complete" else 0)


# --------------------------------------------------------------------------- #
# Durable state
# --------------------------------------------------------------------------- #


@dataclass
class BackfillState:
    """The ``ingest.backfill_state`` row, as the rest of the code sees it."""

    job_name: str = JOB_NAME
    status: str = "pending"
    expected: int = 0
    processed: int = 0
    uploaded: int = 0
    already_present: int = 0
    missing_source: int = 0
    hash_mismatch: int = 0
    failed: int = 0
    verified: int = 0
    verify_errors: int = 0
    bytes_uploaded: int = 0
    source_root: str | None = None
    started_at: datetime | None = None
    updated_at: datetime | None = None
    completed_at: datetime | None = None
    last_error: str | None = None

    @property
    def remaining(self) -> int:
        return max(0, self.expected - self.processed)

    @property
    def is_complete(self) -> bool:
        return self.status == "complete"


_STATE_COLUMNS = (
    "job_name, status, expected, processed, uploaded, already_present, "
    "missing_source, hash_mismatch, failed, verified, verify_errors, bytes_uploaded, "
    "source_root, started_at, updated_at, completed_at, last_error"
)

# Columns a progress or result write may set. Anything not listed here
# keeps its stored value, so a partial update cannot blank a counter.
_UPDATABLE = (
    "status",
    "expected",
    "processed",
    "uploaded",
    "already_present",
    "missing_source",
    "hash_mismatch",
    "failed",
    "verified",
    "verify_errors",
    "bytes_uploaded",
    "source_root",
    "started_at",
    "completed_at",
    "last_error",
)


async def read_state(sm: Any) -> BackfillState:
    """Read the durable state row, or a ``pending`` default when absent.

    One primary-key lookup on a one-row table. This is the whole cost
    of starting a service whose migration finished long ago.
    """
    async with sm() as session:
        row = (
            (
                await session.execute(
                    text(f"SELECT {_STATE_COLUMNS} FROM ingest.backfill_state WHERE job_name = :j"),
                    {"j": JOB_NAME},
                )
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        return BackfillState()
    return BackfillState(**dict(row))


async def write_state(sm: Any, **fields: Any) -> BackfillState:
    """Upsert the named columns of the state row and return the result."""
    unknown = set(fields) - set(_UPDATABLE)
    if unknown:
        raise ValueError(f"not updatable backfill_state columns: {sorted(unknown)}")
    cols = list(fields)
    insert_cols = ", ".join(["job_name", *cols, "updated_at"])
    insert_vals = ", ".join([":job_name", *(f":{c}" for c in cols), "now()"])
    updates = ", ".join([*(f"{c} = EXCLUDED.{c}" for c in cols), "updated_at = now()"])
    async with sm() as session:
        row = (
            (
                await session.execute(
                    text(
                        f"INSERT INTO ingest.backfill_state ({insert_cols}) "
                        f"VALUES ({insert_vals}) "
                        f"ON CONFLICT (job_name) DO UPDATE SET {updates} "
                        f"RETURNING {_STATE_COLUMNS}"
                    ),
                    {"job_name": JOB_NAME, **fields},
                )
            )
            .mappings()
            .one()
        )
        await session.commit()
    state = BackfillState(**dict(row))
    _publish_metrics(state)
    return state


# --------------------------------------------------------------------------- #
# Cheap pre-checks
# --------------------------------------------------------------------------- #


def source_has_files(root: Path) -> bool:
    """True if the legacy archive path exists and holds at least one file.

    Stops at the first hit rather than walking the tree, so an archive
    with thousands of files costs the same as one with one.
    """
    if not root.is_dir():
        return False
    return any(p.is_file() and not p.name.endswith(".tmp") for p in root.rglob("*"))


async def has_archive_rows(sm: Any) -> bool:
    """True if anything has ever been ingested. One indexed row read."""
    async with sm() as session:
        found = (
            await session.execute(text("SELECT 1 FROM ingest.game_log_files LIMIT 1"))
        ).scalar_one_or_none()
    return found is not None


# --------------------------------------------------------------------------- #
# One run
# --------------------------------------------------------------------------- #


@dataclass
class RunOutcome:
    """What ``run_once`` did, for callers and for tests."""

    ran: bool
    reason: str
    state: BackfillState
    counts: BackfillCounts | None = None


def classify(counts: BackfillCounts) -> str:
    """Turn a finished pass's counts into a durable status.

    ``complete`` is the only state that stops future boots from
    re-checking, so it is deliberately strict: it means the verify pass
    found an object for every single row.

    ``stalled`` is the honest answer to "the only thing left is rows
    whose source file does not exist". Nothing this job can do will fix
    that, so retrying it automatically on every boot forever would be
    noise. It stays visible in the status payload and in metrics, and a
    manual trigger still re-runs it once the operator has fixed the
    mount or accepted the loss.
    """
    if counts.ok:
        return "complete"
    made_progress = counts.uploaded > 0
    # A store that could not be reached, an upload that errored, or a
    # source file whose bytes did not match its name are all things the
    # next attempt might do better on. "Could not check" is emphatically
    # NOT the same as "not there": folding a transient verify failure
    # into `stalled` would record a migration that actually succeeded as
    # permanently unfinishable.
    retryable = counts.failed > 0 or counts.hash_mismatch > 0 or counts.verify_errors > 0
    if not made_progress and not retryable:
        return "stalled"
    return "incomplete"


async def _reconcile_without_source(
    sm: Any,
    store: ObjectStore,
    source_root: Path,
    key_prefix: str,
    lock: LockStore,
    trigger: str,
    run: JobRun | None,
    release_preacquired: Callable[[], Awaitable[None]],
) -> RunOutcome:
    """Decide "already migrated" vs "mount is missing", by asking the store.

    Runs the migration's own verify pass with nothing to upload. If
    every row already has an object, the migration is genuinely
    finished and gets recorded ``complete``, which is what lets an
    operator remove the legacy mount and never hear about it again. If
    rows are missing, the state stays un-terminal and loud so a
    forgotten mount is visible rather than papered over as "done".
    """
    _log.info(
        "raw archive migration: source %s is empty or not mounted; "
        "checking whether the archive is already migrated",
        source_root,
    )

    async def _verify_only() -> BackfillCounts:
        # An empty source root means locate_source finds nothing, so
        # this uploads nothing by construction: it is a pure read.
        return await run_backfill(sm, store, source_root, key_prefix=key_prefix)

    try:
        counts = await run_locked(JOB_NAME, _verify_only, trigger=trigger, store=lock, run=run)
    except JobAlreadyRunning:
        return RunOutcome(ran=False, reason="locked", state=await read_state(sm))
    except Exception as exc:  # noqa: BLE001  (a failed check must not kill ingest)
        _log.warning("raw archive migration: could not check the object store: %s", exc)
        await release_preacquired()
        state = await write_state(sm, status="incomplete", last_error=str(exc))
        return RunOutcome(ran=False, reason="source_unavailable", state=state)

    if counts.ok:
        state = await write_state(
            sm,
            status="complete",
            expected=counts.expected,
            processed=counts.processed,
            verified=counts.verified,
            verify_errors=0,
            missing_source=0,
            source_root=str(source_root),
            completed_at=datetime.now(UTC),
            last_error=None,
        )
        _log.info(
            "raw archive migration: already complete (%d rows verified in the store, "
            "no legacy archive needed)",
            counts.verified,
        )
        return RunOutcome(ran=False, reason="already_migrated", state=state, counts=counts)

    state = await write_state(
        sm,
        # Not terminal: the operator can fix the mount and it will run.
        status="incomplete",
        expected=counts.expected,
        processed=counts.processed,
        verified=counts.verified,
        verify_errors=counts.verify_errors,
        missing_source=counts.missing_source,
        source_root=str(source_root),
        last_error=(
            f"{counts.expected - counts.verified} of {counts.expected} files are not in the "
            f"object store, and the legacy archive at {source_root} is empty or not mounted. "
            "Point DA_LEGACY_ARCHIVE_SOURCE at the old archive and restart ingest."
        ),
    )
    _log.warning(
        "raw archive migration: %d of %d files are missing from the store and the legacy "
        "archive at %s is not mounted",
        counts.expected - counts.verified,
        counts.expected,
        source_root,
    )
    return RunOutcome(ran=False, reason="source_unavailable", state=state, counts=counts)


async def run_once(
    sm: Any,
    store: ObjectStore,
    source_root: Path,
    *,
    key_prefix: str = "raw",
    trigger: str = TRIGGER_STARTUP,
    lock_store: LockStore | None = None,
    heartbeat_seconds: float | None = None,
    run: JobRun | None = None,
) -> RunOutcome:
    """Migrate the legacy archive once, if there is anything to migrate.

    Returns without running (and says why) when the work is already
    done, when there is nothing to do, when the source is not mounted,
    or when another replica holds the lock.
    """
    from ingest_service.job_lock import get_store as get_lock_store

    lock = lock_store if lock_store is not None else get_lock_store()
    manual = trigger == TRIGGER_MANUAL

    async def _release_preacquired() -> None:
        """Give back a caller-acquired lock we are not going to use.

        The manual endpoint takes the lock before answering so it can
        say 409 on the spot. Every path below that returns without
        reaching ``run_locked`` has to hand it back, or a decision to
        skip would leave the job wedged until the row went stale.
        """
        if run is None:
            return
        try:
            await lock.release(run.job_name, run.run_id)
        except Exception:  # noqa: BLE001  (a failed release only leaves a stale lock)
            _log.warning("could not release the pre-acquired backfill lock", exc_info=True)

    try:
        state = await read_state(sm)
    except Exception:
        # A database hiccup at boot must not silently cost the caller
        # its lock, nor look like a decision.
        await _release_preacquired()
        raise
    _publish_metrics(state)

    # A manual trigger re-runs a completed migration on purpose: because
    # the job is idempotent, re-running it is the supported way to
    # confirm the first run finished.
    if state.is_complete and not manual:
        await _release_preacquired()
        return RunOutcome(ran=False, reason="already_complete", state=state)
    if state.status == "stalled" and not manual:
        await _release_preacquired()
        return RunOutcome(ran=False, reason="stalled", state=state)

    # Nothing has ever been ingested: a fresh install. Record that
    # durably so this is the last boot that asks the question.
    try:
        any_rows = await has_archive_rows(sm)
    except Exception:
        await _release_preacquired()
        raise
    if not any_rows:
        _G_SOURCE_AVAILABLE.set(1 if source_has_files(source_root) else 0)
        await _release_preacquired()
        state = await write_state(
            sm,
            status="complete",
            expected=0,
            processed=0,
            verified=0,
            source_root=str(source_root),
            completed_at=datetime.now(UTC),
            last_error=None,
        )
        _log.info("raw archive migration: nothing to migrate (no ingested files)")
        return RunOutcome(ran=False, reason="no_rows", state=state)

    available = source_has_files(source_root)
    _G_SOURCE_AVAILABLE.set(1 if available else 0)
    if not available:
        # Rows exist but the legacy path holds nothing. Two very
        # different situations look identical from here: the archive was
        # already migrated (by the one-shot job, or by this service on a
        # host whose mount has since been removed, which is the
        # documented end state) or the mount is simply missing.
        #
        # Guessing either way is wrong, so ask the object store instead.
        # One HEAD per row settles it, it happens at most once because
        # the answer is recorded durably, and it is the only cheap way
        # to tell "already done" from "you forgot the mount".
        return await _reconcile_without_source(
            sm, store, source_root, key_prefix, lock, trigger, run, _release_preacquired
        )

    async def _progress(counts: BackfillCounts) -> None:
        await write_state(
            sm,
            status="running",
            expected=counts.expected,
            processed=counts.processed,
            uploaded=counts.uploaded,
            already_present=counts.already_present,
            missing_source=counts.missing_source,
            hash_mismatch=counts.hash_mismatch,
            failed=counts.failed,
            bytes_uploaded=counts.bytes_uploaded,
        )

    async def _runner() -> BackfillCounts:
        # Only the process that actually holds the run reports itself as
        # running. Deriving this from the shared status row would make
        # every idle replica claim to be migrating.
        _G_RUNNING.set(1)
        await write_state(
            sm,
            status="running",
            started_at=datetime.now(UTC),
            source_root=str(source_root),
            last_error=None,
        )
        _log.info("raw archive migration started from %s", source_root)
        return await run_backfill(
            sm,
            store,
            source_root,
            key_prefix=key_prefix,
            on_progress=_progress,
        )

    kwargs: dict[str, Any] = {}
    if heartbeat_seconds is not None:
        kwargs["heartbeat_seconds"] = heartbeat_seconds
    try:
        counts = await run_locked(JOB_NAME, _runner, trigger=trigger, store=lock, run=run, **kwargs)
    except JobAlreadyRunning:
        _log.info("raw archive migration already running elsewhere; skipping")
        return RunOutcome(ran=False, reason="locked", state=await read_state(sm))
    except JobLeaseLost:
        _log.warning("raw archive migration lost its lock mid-run; another owner took over")
        state = await write_state(sm, status="incomplete", last_error="lost the job lock mid-run")
        return RunOutcome(ran=False, reason="lease_lost", state=state)
    except Exception as exc:  # noqa: BLE001  (a failed migration must not kill ingest)
        _log.exception("raw archive migration failed")
        state = await write_state(sm, status="incomplete", last_error=str(exc))
        return RunOutcome(ran=False, reason="error", state=state)
    finally:
        _G_RUNNING.set(0)

    status = classify(counts)
    state = await write_state(
        sm,
        status=status,
        expected=counts.expected,
        processed=counts.processed,
        uploaded=counts.uploaded,
        already_present=counts.already_present,
        missing_source=counts.missing_source,
        hash_mismatch=counts.hash_mismatch,
        failed=counts.failed,
        verified=counts.verified,
        verify_errors=counts.verify_errors,
        bytes_uploaded=counts.bytes_uploaded,
        source_root=str(source_root),
        # Only ever set on success. A later pass that ends incomplete
        # must not erase the record of when the migration first
        # finished; that timestamp is evidence, not scratch space.
        **({"completed_at": datetime.now(UTC)} if status == "complete" else {}),
        last_error=None if status == "complete" else _incomplete_reason(counts),
    )
    _log.info(
        "raw archive migration finished: status=%s expected=%d uploaded=%d "
        "already_present=%d missing_source=%d failed=%d verified=%d",
        status,
        counts.expected,
        counts.uploaded,
        counts.already_present,
        counts.missing_source,
        counts.failed,
        counts.verified,
    )
    return RunOutcome(ran=True, reason=status, state=state, counts=counts)


def _incomplete_reason(counts: BackfillCounts) -> str:
    parts = []
    if counts.missing_source:
        parts.append(f"{counts.missing_source} rows have no source file")
    if counts.failed:
        parts.append(f"{counts.failed} uploads failed")
    if counts.hash_mismatch:
        parts.append(f"{counts.hash_mismatch} source files did not match their sha")
    if counts.verify_errors:
        parts.append(f"{counts.verify_errors} rows could not be checked in the object store")
    if not parts:
        parts.append(f"verified {counts.verified} of {counts.expected} rows")
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# The startup task
# --------------------------------------------------------------------------- #


async def _startup_body(
    sm: Any,
    store: ObjectStore,
    source_root: Path,
    *,
    key_prefix: str,
    retry_seconds: float,
    max_attempts: int,
) -> None:
    """Run the migration, retrying only while another owner holds it."""
    attempts = 0
    # Bounded separately from `attempts`: waiting out somebody else's
    # lock is not a failed attempt, but it still must not loop forever
    # if a lock row somehow never goes stale.
    waits = 0
    max_waits = max_attempts * _MAX_WAITS_PER_ATTEMPT
    while attempts < max_attempts:
        try:
            outcome = await run_once(
                sm, store, source_root, key_prefix=key_prefix, trigger=TRIGGER_STARTUP
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (a boot-time blip must not end the migration)
            # Database or store trouble before the run could even be
            # classified. Count it and try again rather than leaving the
            # migration undone until the next deploy.
            _log.warning("raw archive migration attempt failed; will retry", exc_info=True)
            attempts += 1
            if attempts < max_attempts:
                await asyncio.sleep(retry_seconds)
            continue

        if outcome.reason in {
            "already_complete",
            "already_migrated",
            "no_rows",
            "stalled",
            "source_unavailable",
        }:
            return
        if outcome.reason == "locked":
            # Another replica is migrating, or our own killed
            # predecessor's lock has not expired yet. Neither is an
            # error; wait for the stale window and look again.
            waits += 1
            if waits > max_waits:
                _log.warning(
                    "raw archive migration: the job lock has been held by someone else "
                    "for %d checks; giving up and leaving it to that owner",
                    max_waits,
                )
                return
            await asyncio.sleep(retry_seconds)
            continue
        attempts += 1
        if outcome.state.is_complete:
            return
        if attempts < max_attempts:
            await asyncio.sleep(retry_seconds)
    _log.warning(
        "raw archive migration gave up after %d automatic attempts; "
        "re-run it from the admin settings page once the cause is fixed",
        max_attempts,
    )


def start(
    sm: Any,
    store: ObjectStore,
    source_root: Path,
    *,
    key_prefix: str = "raw",
    retry_seconds: float = RETRY_SECONDS,
    max_attempts: int = MAX_AUTO_ATTEMPTS,
) -> asyncio.Task[None]:
    """Create the background migration task. Never awaited by lifespan.

    ``create_task`` schedules the coroutine, it does not execute it, so
    this returns before the first line of the migration runs and
    startup completes at its normal speed.
    """
    _G_RUNNING.set(0)

    async def _guarded() -> None:
        try:
            await _startup_body(
                sm,
                store,
                source_root,
                key_prefix=key_prefix,
                retry_seconds=retry_seconds,
                max_attempts=max_attempts,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (never take the service down with it)
            _log.exception("raw archive migration task crashed")
        finally:
            _G_RUNNING.set(0)

    return asyncio.create_task(_guarded(), name="ingest-raw-backfill")


# --------------------------------------------------------------------------- #
# Status payload
# --------------------------------------------------------------------------- #


async def status_payload(sm: Any, source_root: Path, *, enabled: bool) -> dict[str, Any]:
    """Everything an operator needs to answer "is the migration done?".

    Deliberately cheap: one state-row read and one lock-row read. Safe
    to poll from the admin page.
    """
    from ingest_service.job_lock import get_store as get_lock_store

    state = await read_state(sm)
    run = await get_lock_store().read(JOB_NAME)
    payload: dict[str, Any] = {
        "job_name": JOB_NAME,
        "enabled": enabled,
        "status": state.status,
        "expected": state.expected,
        "processed": state.processed,
        "remaining": state.remaining,
        "uploaded": state.uploaded,
        "already_present": state.already_present,
        "missing_source": state.missing_source,
        "hash_mismatch": state.hash_mismatch,
        "failed": state.failed,
        "verified": state.verified,
        "verify_errors": state.verify_errors,
        "bytes_uploaded": state.bytes_uploaded,
        "source_root": state.source_root or str(source_root),
        "source_available": source_has_files(source_root),
        "started_at": state.started_at,
        "updated_at": state.updated_at,
        "completed_at": state.completed_at,
        "last_error": state.last_error,
    }
    payload.update(run_status_fields(run))
    return payload
