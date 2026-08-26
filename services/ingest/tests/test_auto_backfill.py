"""The legacy-archive migration runs itself (issue #161).

#135 shipped the migration as a hand-run one-shot. Until somebody
remembered to run it, every re-read of a raw log failed. These tests
are about the four properties that make running it automatically safe
rather than reckless: it does not hold up startup, only one replica
does it, a kill mid-run resumes instead of restarting, and a finished
migration costs nothing on later boots. Plus the one property that has
been true since #135 and must stay true: it never deletes the source.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from ingest_service import auto_backfill, job_lock
from ingest_service.auto_backfill import (
    JOB_NAME,
    BackfillCounts,
    classify,
    read_state,
    run_once,
    status_payload,
)
from sqlalchemy import text

from common.job_lock import TRIGGER_MANUAL, TRIGGER_STARTUP, PostgresJobLockStore
from common.storage import S3Config, S3ObjectStore, object_key

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


@pytest.fixture
def key_prefix() -> str:
    """A bucket namespace of this test's own.

    The suite's bucket is session-scoped and keys are content-addressed,
    so two tests that seed the same bytes would otherwise see each
    other's objects and "already present" would stop meaning anything.
    """
    return f"raw-{uuid.uuid4().hex[:12]}"


@pytest_asyncio.fixture
async def store(object_store_server: str, key_prefix: str) -> AsyncIterator[S3ObjectStore]:
    """A store whose HTTP connections are closed when the test ends.

    Leaving them open keeps a keep-alive socket on the in-process moto
    server, which then blocks its shutdown at the end of the session.
    """
    st = S3ObjectStore(
        S3Config(
            endpoint_url=object_store_server,
            access_key="test",
            secret_key="testsecret",
            bucket="test-raw",
            region="us-east-1",
            force_path_style=True,
            key_prefix=key_prefix,
        )
    )
    try:
        yield st
    finally:
        await st.aclose()


@pytest.fixture
def lock_store(sessionmaker_factory: Any) -> PostgresJobLockStore:
    """The real Postgres lock, on the real ingest.job_runs table."""
    return PostgresJobLockStore(sessionmaker_factory, table=job_lock.JOB_RUNS_TABLE)


async def _seed(sm: Any, root: Path, count: int) -> dict[str, bytes]:
    """Write ``count`` legacy files and their database rows.

    Bodies carry a per-call salt so no two tests produce the same sha,
    and therefore never the same object key.
    """
    salt = uuid.uuid4().hex
    bodies: dict[str, bytes] = {}
    async with sm() as session:
        for i in range(count):
            body = f"legacy game log {salt} {i}\n".encode()
            sha = hashlib.sha256(body).hexdigest()
            shard = root / sha[0:2] / sha[2:4]
            shard.mkdir(parents=True, exist_ok=True)
            (shard / f"{sha}.dat").write_bytes(body)
            await session.execute(
                text(
                    "INSERT INTO ingest.game_log_files "
                    "(sha256, size_bytes, content_type, storage_path) "
                    "VALUES (:sha, :size, 'match-log', :sp)"
                ),
                {"sha": sha, "size": len(body), "sp": f"{sha[0:2]}/{sha[2:4]}/{sha}.dat"},
            )
            bodies[sha] = body
        await session.commit()
    return bodies


def _keys_in_bucket(s3_client: Any, prefix: str) -> set[str]:
    resp = s3_client.list_objects_v2(Bucket="test-raw", Prefix=f"{prefix}/")
    return {obj["Key"] for obj in resp.get("Contents", [])}


class _CountingStore:
    """Wraps the real store and counts puts, optionally stalling on one.

    Used to hold a migration open long enough to look at it from the
    outside, and to cut one off partway through.
    """

    def __init__(self, inner: S3ObjectStore, *, stall_after: int | None = None) -> None:
        self._inner = inner
        self.puts = 0
        self.landed = 0
        self.stall_after = stall_after
        self.stalled = asyncio.Event()
        self.release = asyncio.Event()

    async def exists(self, key: str) -> bool:
        return await self._inner.exists(key)

    async def put(
        self, key: str, body: bytes, *, content_type: str = "application/octet-stream"
    ) -> None:
        # Claim the slot BEFORE the first await. The migration uploads
        # concurrently, so checking the counter and then awaiting would
        # let every in-flight put read the same pre-increment value and
        # sail past the stall.
        self.puts += 1
        if self.stall_after is not None and self.puts > self.stall_after:
            self.stalled.set()
            await self.release.wait()
        await self._inner.put(key, body, content_type=content_type)
        self.landed += 1

    async def get(self, key: str) -> bytes:
        return await self._inner.get(key)

    async def delete(self, key: str) -> None:  # pragma: no cover - never called
        raise AssertionError("the migration must never delete anything")

    async def ensure_bucket(self) -> bool:
        return await self._inner.ensure_bucket()

    async def aclose(self) -> None:
        await self._inner.aclose()


async def _wait_until_stalled(store: _CountingStore, task: asyncio.Task[Any]) -> None:
    """Block until the migration is provably mid-flight.

    Fails loudly if it finished instead of stalling, rather than timing
    out with no explanation of what the migration actually did.
    """
    watch = asyncio.ensure_future(store.stalled.wait())
    try:
        done, _ = await asyncio.wait({task, watch}, timeout=15, return_when=asyncio.FIRST_COMPLETED)
    finally:
        watch.cancel()
    if store.stalled.is_set():
        # The stall fires when a put ENTERS the wrapper, which can be
        # before the puts ahead of it have finished landing. Settle
        # those first so a caller that inspects the bucket sees exactly
        # the objects that made it through.
        deadline = time.monotonic() + 15
        while store.landed < (store.stall_after or 0) and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        return
    if task in done:
        raise AssertionError(f"the migration finished instead of stalling: {task.result()!r}")
    raise AssertionError(f"the migration never reached its stall point (puts={store.puts})")


# --------------------------------------------------------------------------- #
# It runs, and it migrates
# --------------------------------------------------------------------------- #


async def test_startup_run_migrates_pending_objects(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    s3_client: Any,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    bodies = await _seed(sessionmaker_factory, tmp_path, 5)

    outcome = await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        trigger=TRIGGER_STARTUP,
        lock_store=lock_store,
    )

    assert outcome.ran is True
    assert outcome.reason == "complete"
    assert outcome.counts is not None
    assert outcome.counts.expected == 5
    assert outcome.counts.uploaded == 5
    assert outcome.counts.verified == 5

    # The bytes are really in the store, under the content-addressed key.
    for sha, body in bodies.items():
        key = object_key(sha, key_prefix)
        assert s3_client.get_object(Bucket="test-raw", Key=key)["Body"].read() == body

    state = await read_state(sessionmaker_factory)
    assert state.status == "complete"
    assert state.completed_at is not None


async def test_a_legacy_sha_becomes_readable_after_the_migration(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    """The whole point: a raw read that used to fail now succeeds.

    This is the ``RawFileNotFoundError`` the parser raises, expressed at
    the storage layer the parser reads through.
    """
    bodies = await _seed(sessionmaker_factory, tmp_path, 1)
    sha, body = next(iter(bodies.items()))
    key = object_key(sha, key_prefix)

    assert await store.exists(key) is False

    await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        lock_store=lock_store,
    )

    assert await store.exists(key) is True
    assert await store.get(key) == body


async def test_the_source_is_never_deleted(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    bodies = await _seed(sessionmaker_factory, tmp_path, 3)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert len(before) == 3

    await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        lock_store=lock_store,
    )

    after = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert after == before
    assert set(bodies) == {p.name.split(".")[0] for p in after}


# --------------------------------------------------------------------------- #
# It does not hold up startup
# --------------------------------------------------------------------------- #


async def test_lifespan_returns_and_healthz_answers_while_migrating(
    sessionmaker_factory: Any,
    lock_store: PostgresJobLockStore,
    redis_client: Any,
    object_store_server: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readiness must not wait on a 5,000-object migration."""
    from httpx import ASGITransport, AsyncClient
    from ingest_service import main as _main
    from ingest_service import settings as _settings

    await _seed(sessionmaker_factory, tmp_path, 1)

    started = asyncio.Event()
    release = asyncio.Event()

    async def _slow_backfill(*_args: Any, **_kwargs: Any) -> BackfillCounts:
        started.set()
        await release.wait()
        return BackfillCounts(expected=1, processed=1, verified=1, already_present=1)

    monkeypatch.setattr(auto_backfill, "run_backfill", _slow_backfill)
    monkeypatch.setenv("DA_LEGACY_ARCHIVE_PATH", str(tmp_path))
    monkeypatch.setenv("DA_S3_AUTO_BACKFILL", "true")
    _settings.reset_settings()
    job_lock.set_store(lock_store)

    try:
        t0 = time.monotonic()
        async with _main.lifespan(_main.app):
            # Startup returned without the migration having finished.
            assert time.monotonic() - t0 < 2.0
            await asyncio.wait_for(started.wait(), timeout=10)
            assert not release.is_set()

            transport = ASGITransport(app=_main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.get("/healthz")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

            release.set()
    finally:
        job_lock.set_store(None)
        _settings.reset_settings()


async def test_disabled_by_config_does_not_run(
    sessionmaker_factory: Any,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ingest_service import main as _main
    from ingest_service import settings as _settings

    await _seed(sessionmaker_factory, tmp_path, 2)

    called = False

    async def _never(*_args: Any, **_kwargs: Any) -> BackfillCounts:  # pragma: no cover
        nonlocal called
        called = True
        return BackfillCounts()

    monkeypatch.setattr(auto_backfill, "run_backfill", _never)
    monkeypatch.setenv("DA_LEGACY_ARCHIVE_PATH", str(tmp_path))
    monkeypatch.setenv("DA_S3_AUTO_BACKFILL", "false")
    _settings.reset_settings()
    job_lock.set_store(lock_store)

    try:
        async with _main.lifespan(_main.app):
            # Give any (wrongly) scheduled task a chance to run.
            await asyncio.sleep(0.2)
        assert called is False
        state = await read_state(sessionmaker_factory)
        assert state.status == "pending"
    finally:
        job_lock.set_store(None)
        _settings.reset_settings()


# --------------------------------------------------------------------------- #
# Only one replica migrates
# --------------------------------------------------------------------------- #


async def test_two_concurrent_instances_only_one_migrates(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    """The #155 hazard, on the ingest side: two replicas, one migration."""
    await _seed(sessionmaker_factory, tmp_path, 4)
    slow = _CountingStore(store, stall_after=1)

    async def _instance(obj_store: Any) -> Any:
        return await run_once(
            sessionmaker_factory,
            obj_store,
            tmp_path,
            key_prefix=key_prefix,
            trigger=TRIGGER_STARTUP,
            lock_store=lock_store,
        )

    first = asyncio.create_task(_instance(slow))
    # Wait until the first instance is demonstrably inside the migration
    # before the second one starts, so this tests the lock and not a race.
    await _wait_until_stalled(slow, first)
    second = await _instance(store)
    slow.release.set()
    first_outcome = await first

    assert second.ran is False
    assert second.reason == "locked"
    assert first_outcome.ran is True
    assert first_outcome.counts is not None
    assert first_outcome.counts.uploaded == 4

    # And the lock row is gone once the winner finishes.
    assert await lock_store.read(JOB_NAME) is None


# --------------------------------------------------------------------------- #
# A kill mid-migration resumes
# --------------------------------------------------------------------------- #


async def test_restart_mid_migration_resumes_without_duplicating(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    s3_client: Any,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    bodies = await _seed(sessionmaker_factory, tmp_path, 6)
    cut = _CountingStore(store, stall_after=2)

    killed = asyncio.create_task(
        run_once(
            sessionmaker_factory,
            cut,
            tmp_path,
            key_prefix=key_prefix,
            lock_store=lock_store,
        )
    )
    await _wait_until_stalled(cut, killed)
    partial_keys = _keys_in_bucket(s3_client, key_prefix)
    assert 0 < len(partial_keys) < 6

    # The container dies partway through.
    killed.cancel()
    with pytest.raises(asyncio.CancelledError):
        await killed
    # Cancellation stops the migration itself, not just the wrapper, so
    # nothing is still writing behind the resumed run.
    assert await lock_store.read(JOB_NAME) is None
    cut.release.set()

    state = await read_state(sessionmaker_factory)
    assert state.status != "complete"

    # It comes back up and picks up where it left off.
    resumed = await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        lock_store=lock_store,
    )

    assert resumed.ran is True
    assert resumed.reason == "complete"
    assert resumed.counts is not None
    assert resumed.counts.expected == 6
    assert resumed.counts.verified == 6
    # Work already done is recognised, not redone.
    assert resumed.counts.already_present == len(partial_keys)
    assert resumed.counts.uploaded == 6 - len(partial_keys)

    # Nothing is duplicated and nothing is corrupt: one object per sha,
    # each holding exactly the source bytes.
    assert _keys_in_bucket(s3_client, key_prefix) == {object_key(sha, key_prefix) for sha in bodies}
    for sha, body in bodies.items():
        key = object_key(sha, key_prefix)
        assert s3_client.get_object(Bucket="test-raw", Key=key)["Body"].read() == body


# --------------------------------------------------------------------------- #
# Nothing to do is cheap
# --------------------------------------------------------------------------- #


async def test_fresh_install_with_no_ingested_files_is_a_noop(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key_prefix: str,
) -> None:
    async def _never(*_args: Any, **_kwargs: Any) -> BackfillCounts:  # pragma: no cover
        raise AssertionError("a fresh install must not walk the archive")

    monkeypatch.setattr(auto_backfill, "run_backfill", _never)

    outcome = await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        lock_store=lock_store,
    )

    assert outcome.ran is False
    assert outcome.reason == "no_rows"
    # Recorded durably, so this is the last boot that asks.
    assert outcome.state.status == "complete"


async def test_a_completed_migration_costs_one_row_read_on_later_boots(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key_prefix: str,
) -> None:
    await _seed(sessionmaker_factory, tmp_path, 3)
    first = await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        lock_store=lock_store,
    )
    assert first.reason == "complete"

    # Anything that would scan rows or walk the archive is now a bug.
    async def _never(*_args: Any, **_kwargs: Any) -> BackfillCounts:  # pragma: no cover
        raise AssertionError("a completed migration must not run again automatically")

    def _no_walk(_root: Path) -> bool:  # pragma: no cover
        raise AssertionError("a completed migration must not walk the archive")

    monkeypatch.setattr(auto_backfill, "run_backfill", _never)
    monkeypatch.setattr(auto_backfill, "source_has_files", _no_walk)

    for _ in range(3):
        again = await run_once(
            sessionmaker_factory,
            store,
            tmp_path,
            key_prefix=key_prefix,
            lock_store=lock_store,
        )
        assert again.ran is False
        assert again.reason == "already_complete"


async def test_a_manual_trigger_reruns_a_completed_migration(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    """Re-running is how an operator confirms the first run finished."""
    await _seed(sessionmaker_factory, tmp_path, 2)
    await run_once(
        sessionmaker_factory, store, tmp_path, key_prefix=key_prefix, lock_store=lock_store
    )

    again = await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        trigger=TRIGGER_MANUAL,
        lock_store=lock_store,
    )
    assert again.ran is True
    assert again.counts is not None
    assert again.counts.uploaded == 0
    assert again.counts.already_present == 2
    assert again.counts.verified == 2


async def test_rows_with_no_mounted_source_do_not_record_completion(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    """A forgotten mount must stay visible, not be recorded as done."""
    seeded = tmp_path / "seeded"
    seeded.mkdir()
    await _seed(sessionmaker_factory, seeded, 2)

    empty = tmp_path / "not-mounted"
    empty.mkdir()
    outcome = await run_once(
        sessionmaker_factory,
        store,
        empty,
        key_prefix=key_prefix,
        lock_store=lock_store,
    )

    assert outcome.ran is False
    assert outcome.reason == "source_unavailable"
    assert outcome.state.status != "complete"
    assert outcome.state.last_error is not None


# --------------------------------------------------------------------------- #
# Observability
# --------------------------------------------------------------------------- #


async def test_status_payload_reports_progress_without_reading_logs(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    await _seed(sessionmaker_factory, tmp_path, 3)
    job_lock.set_store(lock_store)
    try:
        before = await status_payload(sessionmaker_factory, tmp_path, enabled=True)
        assert before["status"] == "pending"
        assert before["is_running"] is False
        assert before["source_available"] is True

        await run_once(
            sessionmaker_factory, store, tmp_path, key_prefix=key_prefix, lock_store=lock_store
        )

        after = await status_payload(sessionmaker_factory, tmp_path, enabled=True)
        assert after["status"] == "complete"
        assert after["expected"] == 3
        assert after["processed"] == 3
        assert after["remaining"] == 0
        assert after["verified"] == 3
        assert after["uploaded"] == 3
        assert after["is_running"] is False
        assert after["completed_at"] is not None
    finally:
        job_lock.set_store(None)


async def test_progress_is_visible_while_the_migration_is_still_running(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    await _seed(sessionmaker_factory, tmp_path, 3)
    slow = _CountingStore(store, stall_after=1)
    job_lock.set_store(lock_store)
    try:
        running = asyncio.create_task(
            run_once(
                sessionmaker_factory,
                slow,
                tmp_path,
                key_prefix=key_prefix,
                lock_store=lock_store,
            )
        )
        await _wait_until_stalled(slow, running)

        mid = await status_payload(sessionmaker_factory, tmp_path, enabled=True)
        assert mid["status"] == "running"
        assert mid["is_running"] is True
        assert mid["running_since"] is not None
        assert mid["expected"] == 3

        slow.release.set()
        await running
    finally:
        job_lock.set_store(None)


# --------------------------------------------------------------------------- #
# Admin endpoints
# --------------------------------------------------------------------------- #


async def test_admin_status_requires_an_admin_token(client: Any) -> None:
    assert (await client.get("/ingest/admin/raw-backfill")).status_code == 401
    resp = await client.get(
        "/ingest/admin/raw-backfill", headers={"Authorization": "Bearer nonsense"}
    )
    assert resp.status_code == 401


async def test_admin_status_rejects_a_non_admin_user(client: Any) -> None:
    token = _mint_token(role="user")
    resp = await client.get(
        "/ingest/admin/raw-backfill", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403


async def test_admin_status_returns_the_payload_for_an_admin(
    client: Any, sessionmaker_factory: Any, lock_store: PostgresJobLockStore, tmp_path: Path
) -> None:
    from ingest_service import deps as _deps
    from ingest_service import settings as _settings

    os.environ["DA_LEGACY_ARCHIVE_PATH"] = str(tmp_path)
    _settings.reset_settings()
    _deps.reset_verifier()
    job_lock.set_store(lock_store)
    try:
        token = _mint_token(role="admin")
        resp = await client.get(
            "/ingest/admin/raw-backfill", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["job_name"] == JOB_NAME
        assert body["enabled"] is True
        assert body["status"] == "pending"
        assert body["is_running"] is False
    finally:
        job_lock.set_store(None)
        os.environ.pop("DA_LEGACY_ARCHIVE_PATH", None)
        _settings.reset_settings()
        _deps.reset_verifier()


def _mint_token(*, role: str, user_id: int = 1) -> str:
    """Sign an access token with the suite's JWT private key."""
    import time as _time

    import jwt

    key = Path(os.environ["DA_JWT_PRIVATE_KEY_PATH"]).read_bytes()
    now = int(_time.time())
    return jwt.encode(
        {
            "sub": str(user_id),
            "role": role,
            "iss": "deep-analysis-auth",
            "aud": "deep-analysis",
            "iat": now,
            "exp": now + 300,
        },
        key,
        algorithm="RS256",
    )


# --------------------------------------------------------------------------- #
# classify(): the function that decides whether a migration is permanently done
# --------------------------------------------------------------------------- #


async def test_classify_complete_needs_every_row_verified() -> None:
    assert classify(BackfillCounts(expected=3, processed=3, uploaded=3, verified=3)) == "complete"


async def test_classify_partial_verification_is_not_complete() -> None:
    counts = BackfillCounts(expected=3, processed=3, uploaded=3, verified=2)
    assert counts.ok is False
    assert classify(counts) == "incomplete"


async def test_classify_only_unfixable_rows_left_is_stalled() -> None:
    """Nothing this job can do will find a file that does not exist.

    Retrying that on every boot forever is noise, so it is terminal for
    the automatic path (and only for that path).
    """
    counts = BackfillCounts(
        expected=3, processed=3, uploaded=0, already_present=2, missing_source=1
    )
    assert classify(counts) == "stalled"


async def test_classify_treats_a_failed_upload_as_retryable() -> None:
    counts = BackfillCounts(expected=3, processed=3, uploaded=0, already_present=2, failed=1)
    assert classify(counts) == "incomplete"


async def test_classify_does_not_strand_a_run_on_an_unreachable_store() -> None:
    """ "Could not check" is not "not there".

    Folding a transient verify failure into ``stalled`` would record a
    migration that actually succeeded as permanently unfinishable, and
    an operator would have to notice and click a button to undo it.
    """
    counts = BackfillCounts(
        expected=3, processed=3, uploaded=0, already_present=3, verified=2, verify_errors=1
    )
    assert counts.ok is False
    assert classify(counts) == "incomplete"


async def test_stalled_is_terminal_for_startup_but_not_for_a_manual_run(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A row whose source file does not exist: nothing to migrate, ever.
    async with sessionmaker_factory() as session:
        await session.execute(
            text(
                "INSERT INTO ingest.game_log_files "
                "(sha256, size_bytes, content_type, storage_path) "
                "VALUES (:sha, 10, 'match-log', 'x')"
            ),
            {"sha": "f" * 64},
        )
        await session.commit()
    (tmp_path / "unrelated.dat").write_bytes(b"not a game log")

    first = await run_once(
        sessionmaker_factory, store, tmp_path, key_prefix=key_prefix, lock_store=lock_store
    )
    assert first.state.status == "stalled"

    async def _never(*_args: Any, **_kwargs: Any) -> BackfillCounts:  # pragma: no cover
        raise AssertionError("a stalled migration must not auto-retry")

    monkeypatch.setattr(auto_backfill, "run_backfill", _never)
    skipped = await run_once(
        sessionmaker_factory, store, tmp_path, key_prefix=key_prefix, lock_store=lock_store
    )
    assert skipped.ran is False
    assert skipped.reason == "stalled"

    # An operator asking explicitly still gets a run.
    monkeypatch.undo()
    manual = await run_once(
        sessionmaker_factory,
        store,
        tmp_path,
        key_prefix=key_prefix,
        trigger=TRIGGER_MANUAL,
        lock_store=lock_store,
    )
    assert manual.ran is True


# --------------------------------------------------------------------------- #
# The mount is gone but the work was already done
# --------------------------------------------------------------------------- #


async def test_an_already_migrated_host_with_no_mount_records_completion(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    """The documented end state: mount removed after the migration ran.

    Also covers the host that ran the #135 one-shot by hand and so has
    no state row at all. Neither may sit on a permanent false alarm.
    """
    seeded = tmp_path / "seeded"
    seeded.mkdir()
    bodies = await _seed(sessionmaker_factory, seeded, 3)
    for sha, body in bodies.items():
        await store.put(object_key(sha, key_prefix), body, content_type="application/octet-stream")

    gone = tmp_path / "no-longer-mounted"
    gone.mkdir()
    outcome = await run_once(
        sessionmaker_factory, store, gone, key_prefix=key_prefix, lock_store=lock_store
    )

    assert outcome.reason == "already_migrated"
    assert outcome.state.status == "complete"
    assert outcome.state.verified == 3
    assert outcome.state.last_error is None
    # And it never asks again.
    assert await lock_store.read(JOB_NAME) is None


async def test_a_missing_mount_with_unmigrated_rows_stays_loud(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    seeded = tmp_path / "seeded"
    seeded.mkdir()
    await _seed(sessionmaker_factory, seeded, 3)

    gone = tmp_path / "no-longer-mounted"
    gone.mkdir()
    outcome = await run_once(
        sessionmaker_factory, store, gone, key_prefix=key_prefix, lock_store=lock_store
    )

    assert outcome.reason == "source_unavailable"
    assert outcome.state.status != "complete"
    assert outcome.state.last_error is not None
    assert "not mounted" in outcome.state.last_error
    assert await lock_store.read(JOB_NAME) is None


# --------------------------------------------------------------------------- #
# Cancellation
# --------------------------------------------------------------------------- #


async def test_cancelling_the_run_stops_the_work_before_the_lock_is_released(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    """A SIGTERM during a migration must not leave it running unlocked.

    ``asyncio.wait`` does not cancel what it waits on, so without an
    explicit cancel the migration would carry on writing objects while
    the lock row is deleted, and a second replica could legitimately
    acquire and run alongside it.
    """
    await _seed(sessionmaker_factory, tmp_path, 6)
    slow = _CountingStore(store, stall_after=1)

    task = asyncio.create_task(
        run_once(sessionmaker_factory, slow, tmp_path, key_prefix=key_prefix, lock_store=lock_store)
    )
    await _wait_until_stalled(slow, task)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The lock is free, and nothing is still uploading behind it: let the
    # stalled put through and confirm no further object lands.
    assert await lock_store.read(JOB_NAME) is None
    landed_at_cancel = slow.landed
    slow.release.set()
    await asyncio.sleep(0.3)
    assert slow.landed == landed_at_cancel


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


async def test_gauges_report_the_migration_without_reading_logs(
    sessionmaker_factory: Any,
    store: S3ObjectStore,
    lock_store: PostgresJobLockStore,
    tmp_path: Path,
    key_prefix: str,
) -> None:
    from prometheus_client import REGISTRY

    def gauge(name: str) -> float:
        value = REGISTRY.get_sample_value(name)
        assert value is not None, f"{name} is not registered"
        return value

    await _seed(sessionmaker_factory, tmp_path, 4)
    await run_once(
        sessionmaker_factory, store, tmp_path, key_prefix=key_prefix, lock_store=lock_store
    )

    assert gauge("ingest_raw_backfill_expected") == 4
    assert gauge("ingest_raw_backfill_processed") == 4
    assert gauge("ingest_raw_backfill_remaining") == 0
    assert gauge("ingest_raw_backfill_uploaded") == 4
    assert gauge("ingest_raw_backfill_failed") == 0
    assert gauge("ingest_raw_backfill_verify_errors") == 0
    assert gauge("ingest_raw_backfill_complete") == 1
    # Per-process, not derived from the shared row: this process is done.
    assert gauge("ingest_raw_backfill_running") == 0
    assert gauge("ingest_raw_backfill_source_available") == 1
