"""Analytics background loops under the shared job lock (issue #155).

A "replica" here is a second concurrent caller of the same loop entry
point. Both share one ``InMemoryJobLockStore``, which stands in for the
``analytics.scraper_runs`` table two real replicas would both see, and
its injectable clock lets a test age a lock without sleeping. The SQL
behind the Postgres store is covered by
``tests/integration/test_scraper_run_lock_pg.py``.

Covered per loop:

* two replicas starting together run the locked loop once (AC1);
* a holder killed without releasing is taken over once its row is older
  than ``STALE_AFTER_SECONDS`` (AC2);
* the cache invalidator, deliberately unlocked, runs on every replica.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from analytics_service import card_materializer, scraper_lock, scryfall_sync
from analytics_service import main as analytics_main
from analytics_service.card_materializer import (
    BACKFILL_JOB_NAME,
    MATERIALIZER_JOB_NAME,
    backfill_card_stats_if_idle,
    card_stats_backfill_loop,
    locked_card_materializer_loop,
)
from analytics_service.scryfall_sync import JOB_NAME as SCRYFALL_JOB
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common import job_lock
from common.job_lock import (
    STALE_AFTER_SECONDS,
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    TRIGGER_STARTUP,
    InMemoryJobLockStore,
    acquire,
    run_locked_standby,
)

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Settings the loops read at start (``redis_url``), without a stack."""
    out = tmp_path_factory.mktemp("loop-lock-jwt-keys")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.environ.setdefault("DA_JWT_PUBLIC_KEY_PATH", str(pub_path))
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    yield pub_path


class _Clock:
    """Manually advanced clock so staleness is testable without sleeping."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def store(clock: _Clock) -> InMemoryJobLockStore:
    return InMemoryJobLockStore(stale_after_seconds=STALE_AFTER_SECONDS, clock=clock)


@pytest.fixture
def installed_store(store: InMemoryJobLockStore) -> Iterator[InMemoryJobLockStore]:
    """Bind the process-wide analytics store to the in-memory one."""
    scraper_lock.set_store(store)
    yield store
    scraper_lock.set_store(None)


class _FakeSession:
    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


def _fake_sessionmaker() -> Any:
    return _FakeSession()


class _Stepper:
    """Replaces a sleep with a wait the test releases one step at a time."""

    def __init__(self) -> None:
        self.calls: list[float] = []
        self._gate = asyncio.Event()

    async def sleep(self, seconds: float) -> None:
        self.calls.append(seconds)
        await self._gate.wait()
        self._gate.clear()

    def step(self) -> None:
        self._gate.set()


async def _settle(rounds: int = 50) -> None:
    """Let every ready task run; the in-memory store never blocks."""
    for _ in range(rounds):
        await asyncio.sleep(0)


async def _cancel(*tasks: asyncio.Task[Any]) -> None:
    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[httpx.AsyncClient]:
    """ASGI client for the analytics app with admin auth stubbed out."""
    from analytics_service.deps import AuthenticatedUser, require_admin

    app = analytics_main.app
    app.dependency_overrides[require_admin] = lambda: AuthenticatedUser(user_id=1, role="admin")
    monkeypatch.setattr(analytics_main, "get_sessionmaker", lambda: _fake_sessionmaker)
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://analytics")
    yield client
    app.dependency_overrides.pop(require_admin, None)


# --------------------------------------------------------------------------- #
# Scryfall scheduler: locked per tick, due check inside the lock
# --------------------------------------------------------------------------- #


@pytest.fixture
def scryfall_fakes(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """``should_sync`` always due; ``run_sync`` records and waits for release."""
    state: dict[str, Any] = {"syncs": 0, "started": asyncio.Event(), "release": asyncio.Event()}
    state["release"].set()

    async def fake_should_sync(_session: Any) -> bool:
        return True

    async def fake_run_sync(_sm: Any) -> Any:
        state["syncs"] += 1
        state["started"].set()
        await state["release"].wait()
        return None

    monkeypatch.setattr(scryfall_sync, "should_sync", fake_should_sync)
    monkeypatch.setattr(scryfall_sync, "run_sync", fake_run_sync)
    monkeypatch.setattr(analytics_main, "get_sessionmaker", lambda: _fake_sessionmaker)
    return state


async def test_two_replicas_ticking_together_sync_once(
    installed_store: InMemoryJobLockStore, scryfall_fakes: dict[str, Any]
) -> None:
    """AC1: both replicas boot, both find the mirror due, one downloads."""
    scryfall_fakes["release"].clear()

    first = asyncio.create_task(analytics_main._scryfall_tick())
    await scryfall_fakes["started"].wait()
    second = asyncio.create_task(analytics_main._scryfall_tick())
    await second  # the loser skips its tick while the winner is mid-download
    assert scryfall_fakes["syncs"] == 1

    held = await installed_store.read(SCRYFALL_JOB)
    assert held is not None and held.is_live and held.trigger == TRIGGER_SCHEDULED

    scryfall_fakes["release"].set()
    await first
    assert scryfall_fakes["syncs"] == 1
    assert await installed_store.read(SCRYFALL_JOB) is None


async def test_due_check_is_repeated_inside_the_lock(
    installed_store: InMemoryJobLockStore,
    scryfall_fakes: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replica queued behind a finished sync re-reads synced_at and does nothing."""
    verdicts = iter([True, False])

    async def should_sync_once(_session: Any) -> bool:
        return next(verdicts)

    monkeypatch.setattr(scryfall_sync, "should_sync", should_sync_once)

    await analytics_main._scryfall_tick()
    await analytics_main._scryfall_tick()
    assert scryfall_fakes["syncs"] == 1


async def test_scheduled_sync_takes_over_a_killed_holders_lock(
    installed_store: InMemoryJobLockStore, scryfall_fakes: dict[str, Any], clock: _Clock
) -> None:
    """AC2: a row left behind by a SIGKILLed replica stops blocking after STALE_AFTER_SECONDS."""
    zombie = await acquire(SCRYFALL_JOB, trigger=TRIGGER_SCHEDULED, store=installed_store)

    await analytics_main._scryfall_tick()
    assert scryfall_fakes["syncs"] == 0, "a fresh row still counts as a live run"

    clock.advance(STALE_AFTER_SECONDS - 1)
    await analytics_main._scryfall_tick()
    assert scryfall_fakes["syncs"] == 0

    clock.advance(2)
    await analytics_main._scryfall_tick()
    assert scryfall_fakes["syncs"] == 1
    assert await installed_store.read(SCRYFALL_JOB) is None
    assert zombie.run_id  # the dead run's id is never reused: a new run_id was issued


async def test_manual_sync_runs_under_the_lock_and_frees_it(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryJobLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ran: list[bool] = []

    async def fake_run_sync(_sm: Any) -> Any:
        run = await installed_store.read(SCRYFALL_JOB)
        ran.append(bool(run and run.is_live and run.trigger == TRIGGER_MANUAL))
        return None

    monkeypatch.setattr(analytics_main, "run_sync", fake_run_sync)

    resp = await admin_client.post("/analytics/admin/sync-cards")
    assert resp.status_code == 202
    assert resp.json()["status"] == "sync_started"
    assert ran == [True], "the background sync must run under the manual lock"
    assert await installed_store.read(SCRYFALL_JOB) is None


async def test_manual_sync_is_refused_while_the_scheduler_syncs(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryJobLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def fake_run_sync(_sm: Any) -> Any:
        calls.append("ran")
        return None

    monkeypatch.setattr(analytics_main, "run_sync", fake_run_sync)
    active = await acquire(SCRYFALL_JOB, trigger=TRIGGER_SCHEDULED, store=installed_store)

    resp = await admin_client.post("/analytics/admin/sync-cards")
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "sync_already_running"
    assert body["job_name"] == SCRYFALL_JOB
    assert body["running_since"] == active.started_at.isoformat()
    assert body["run_trigger"] == TRIGGER_SCHEDULED
    assert calls == [], "no duplicate sync may start"


# --------------------------------------------------------------------------- #
# Card materializer: one subscriber, held as a lease, standby takes over
# --------------------------------------------------------------------------- #


@pytest.fixture
def materializer_fakes(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The subscriber body records a start and then runs until cancelled."""
    state: dict[str, Any] = {"starts": 0, "standby": _Stepper()}

    async def fake_subscriber(_redis_url: str, _sm: Any) -> None:
        state["starts"] += 1
        await asyncio.Event().wait()

    monkeypatch.setattr(card_materializer, "card_materializer_loop", fake_subscriber)
    monkeypatch.setattr(job_lock, "_async_sleep", state["standby"].sleep)
    return state


async def test_two_replicas_start_one_materializer(
    store: InMemoryJobLockStore, materializer_fakes: dict[str, Any]
) -> None:
    """AC1: one subscriber; the other replica stands by instead of subscribing."""
    tasks = [
        asyncio.create_task(
            locked_card_materializer_loop(
                "redis://fake", _fake_sessionmaker, store=store, retry_seconds=7.0
            )
        )
        for _ in range(2)
    ]
    await _settle()

    assert materializer_fakes["starts"] == 1
    assert materializer_fakes["standby"].calls == [7.0], "the loser waits, it does not spin"
    held = await store.read(MATERIALIZER_JOB_NAME)
    assert held is not None and held.is_live and held.trigger == TRIGGER_STARTUP

    await _cancel(*tasks)
    assert await store.read(MATERIALIZER_JOB_NAME) is None, "shutdown releases the lease"


async def test_standby_takes_over_after_the_holder_is_killed(
    store: InMemoryJobLockStore, materializer_fakes: dict[str, Any], clock: _Clock
) -> None:
    """AC2: the standby's retry acquires the row once it is older than STALE_AFTER_SECONDS."""
    zombie = await acquire(MATERIALIZER_JOB_NAME, trigger=TRIGGER_STARTUP, store=store)
    standby = materializer_fakes["standby"]

    task = asyncio.create_task(
        locked_card_materializer_loop("redis://fake", _fake_sessionmaker, store=store)
    )
    await _settle()
    assert materializer_fakes["starts"] == 0
    assert standby.calls == [job_lock.STANDBY_RETRY_SECONDS]

    clock.advance(STALE_AFTER_SECONDS - 1)
    standby.step()
    await _settle()
    assert materializer_fakes["starts"] == 0, "not stale yet: still refused"
    assert len(standby.calls) == 2

    clock.advance(2)
    standby.step()
    await _settle()
    assert materializer_fakes["starts"] == 1
    current = await store.read(MATERIALIZER_JOB_NAME)
    assert current is not None and current.is_live
    assert current.run_id != zombie.run_id

    await _cancel(task)


async def test_holder_that_loses_its_lease_stops_and_stands_by(
    store: InMemoryJobLockStore, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two live subscribers is the bug; a holder whose row was taken over must stop."""
    standby = _Stepper()
    monkeypatch.setattr(job_lock, "_async_sleep", standby.sleep)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def subscriber() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    task = asyncio.create_task(
        run_locked_standby(
            MATERIALIZER_JOB_NAME,
            subscriber,
            trigger=TRIGGER_STARTUP,
            store=store,
            heartbeat_seconds=0.01,
        )
    )
    await started.wait()

    clock.advance(1000)  # the holder's heartbeat is now hopelessly stale
    thief = await acquire(MATERIALIZER_JOB_NAME, trigger=TRIGGER_STARTUP, store=store)
    for _ in range(200):
        await asyncio.sleep(0.005)
        if cancelled.is_set():
            break

    assert cancelled.is_set(), "the old holder must stop running next to the new owner"
    assert standby.calls, "and go back to standing by for the lock"
    current = await store.read(MATERIALIZER_JOB_NAME)
    assert current is not None and current.run_id == thief.run_id

    await _cancel(task)


# --------------------------------------------------------------------------- #
# Card stats backfill: locked per pass
# --------------------------------------------------------------------------- #


@pytest.fixture
def backfill_fakes(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A pass records itself and waits for release; the interval sleep never ends."""
    state: dict[str, Any] = {"passes": 0, "release": asyncio.Event(), "interval": _Stepper()}
    state["release"].set()

    async def fake_backfill(_sm: Any, batch_size: int = 100) -> int:
        state["passes"] += 1
        await state["release"].wait()
        return 3

    monkeypatch.setattr(card_materializer, "backfill_card_stats", fake_backfill)
    monkeypatch.setattr(card_materializer, "_async_sleep", state["interval"].sleep)
    return state


async def test_two_replicas_scanning_together_backfill_once(
    store: InMemoryJobLockStore, backfill_fakes: dict[str, Any]
) -> None:
    """AC1: two timers fire together; one scan runs, the other skips its turn."""
    backfill_fakes["release"].clear()
    tasks = [
        asyncio.create_task(
            card_stats_backfill_loop(_fake_sessionmaker, interval_seconds=300, store=store)
        )
        for _ in range(2)
    ]
    await _settle()
    assert backfill_fakes["passes"] == 1
    held = await store.read(BACKFILL_JOB_NAME)
    assert held is not None and held.is_live and held.trigger == TRIGGER_SCHEDULED

    backfill_fakes["release"].set()
    await _settle()
    assert backfill_fakes["passes"] == 1
    assert backfill_fakes["interval"].calls == [300, 300], "both replicas keep their timer"
    assert await store.read(BACKFILL_JOB_NAME) is None

    await _cancel(*tasks)


async def test_backfill_pass_takes_over_a_killed_holders_lock(
    store: InMemoryJobLockStore, backfill_fakes: dict[str, Any], clock: _Clock
) -> None:
    """AC2: the survivor's next pass runs once the dead holder's row is stale."""
    await acquire(BACKFILL_JOB_NAME, trigger=TRIGGER_SCHEDULED, store=store)

    assert await backfill_card_stats_if_idle(_fake_sessionmaker, store=store) is None
    assert backfill_fakes["passes"] == 0

    clock.advance(STALE_AFTER_SECONDS + 1)
    assert await backfill_card_stats_if_idle(_fake_sessionmaker, store=store) == 3
    assert backfill_fakes["passes"] == 1
    assert await store.read(BACKFILL_JOB_NAME) is None


async def test_backfill_skip_is_not_an_error(
    store: InMemoryJobLockStore, backfill_fakes: dict[str, Any]
) -> None:
    """A skipped pass must not trip the loop's failure path or stop the timer."""
    await acquire(BACKFILL_JOB_NAME, trigger=TRIGGER_MANUAL, store=store)
    task = asyncio.create_task(
        card_stats_backfill_loop(_fake_sessionmaker, interval_seconds=5, store=store)
    )
    await _settle()
    assert backfill_fakes["passes"] == 0
    assert backfill_fakes["interval"].calls == [5]
    await _cancel(task)


# --------------------------------------------------------------------------- #
# Cache invalidator: deliberately unlocked
# --------------------------------------------------------------------------- #


class _OneMessagePubSub:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    async def subscribe(self, channel: str) -> None:
        return None

    async def listen(self) -> Any:
        yield {"type": "message", "data": json.dumps(self._payload)}
        await asyncio.Event().wait()


async def test_cache_invalidator_runs_on_every_replica(
    installed_store: InMemoryJobLockStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each replica serves the cache, so each must hear the event. No lock."""
    invalidated: list[int] = []

    async def fake_get_redis(_url: str) -> MagicMock:
        client = MagicMock()
        client.pubsub.return_value = _OneMessagePubSub({"match_id": "m1", "user_id": 42})
        return client

    async def fake_invalidate(_client: Any, user_id: int) -> int:
        invalidated.append(user_id)
        return 1

    monkeypatch.setattr(analytics_main, "get_redis", fake_get_redis)
    monkeypatch.setattr(analytics_main, "invalidate_user", fake_invalidate)

    tasks = [asyncio.create_task(analytics_main._cache_invalidation_loop()) for _ in range(2)]
    await _settle()
    assert invalidated == [42, 42], "both replicas invalidate; a second delete is a no-op"
    for job in (SCRYFALL_JOB, MATERIALIZER_JOB_NAME, BACKFILL_JOB_NAME, "cache_invalidator"):
        assert await installed_store.read(job) is None, "the invalidator takes no lock"
    await _cancel(*tasks)
