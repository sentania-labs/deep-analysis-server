"""Per-scraper run lock: acquisition, release, staleness, health shape (#127).

These are unit tests: they drive the lock through ``InMemoryLockStore``,
which mirrors the Postgres store's semantics with an injectable clock so
a lock can be aged without sleeping. The real SQL is exercised against a
live Postgres in ``tests/integration/test_scraper_run_lock_pg.py``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_service import main as analytics_main
from analytics_service import scraper_lock
from analytics_service.scraper_lock import (
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    InMemoryLockStore,
    ScrapeAlreadyRunning,
    ScrapeLeaseLost,
    acquire,
    held,
    run_locked,
    run_status_fields,
)

MTGO = "mtgo"


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


class _Clock:
    """Manually advanced clock so staleness is testable without sleeping."""

    def __init__(self) -> None:
        self.now = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def store(clock: _Clock) -> InMemoryLockStore:
    return InMemoryLockStore(stale_after_seconds=180.0, clock=clock)


@pytest.fixture
def installed_store(store: InMemoryLockStore) -> Any:
    """Bind the process-wide store to the in-memory one for endpoint tests."""
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


@pytest.fixture
def admin_client(monkeypatch: pytest.MonkeyPatch) -> Any:
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
# Acquisition
# --------------------------------------------------------------------------- #


async def test_second_acquire_is_refused_while_a_run_is_live(store: InMemoryLockStore) -> None:
    first = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    with pytest.raises(ScrapeAlreadyRunning) as caught:
        await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    assert caught.value.run.run_id == first.run_id
    assert caught.value.run.started_at == first.started_at


async def test_concurrent_acquires_produce_exactly_one_winner(store: InMemoryLockStore) -> None:
    results = await asyncio.gather(
        *(acquire(MTGO, trigger=TRIGGER_MANUAL, store=store) for _ in range(5)),
        return_exceptions=True,
    )
    winners = [r for r in results if not isinstance(r, BaseException)]
    losers = [r for r in results if isinstance(r, ScrapeAlreadyRunning)]
    assert len(winners) == 1
    assert len(losers) == 4


async def test_lock_is_per_scraper_not_global(store: InMemoryLockStore) -> None:
    await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    other = await acquire("mtgtop8", trigger=TRIGGER_MANUAL, store=store)
    assert other.job_name == "mtgtop8"


# --------------------------------------------------------------------------- #
# Release
# --------------------------------------------------------------------------- #


async def test_lock_released_on_normal_completion(store: InMemoryLockStore) -> None:
    seen: list[bool] = []

    async def runner() -> str:
        run = await store.read(MTGO)
        seen.append(bool(run and run.is_live))
        return "done"

    result = await run_locked(MTGO, runner, trigger=TRIGGER_MANUAL, store=store)
    assert result == "done"
    assert seen == [True], "the lock must be held while the scrape runs"
    assert await store.read(MTGO) is None, "the lock must be gone after completion"


async def test_lock_released_when_the_scrape_raises(store: InMemoryLockStore) -> None:
    async def boom() -> None:
        raise RuntimeError("mtgo.com fell over")

    with pytest.raises(RuntimeError):
        await run_locked(MTGO, boom, trigger=TRIGGER_MANUAL, store=store)
    assert await store.read(MTGO) is None

    # And the next run is free to start.
    await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)


async def test_release_does_not_touch_a_lock_owned_by_someone_else(
    store: InMemoryLockStore, clock: _Clock
) -> None:
    zombie = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    clock.advance(300)  # zombie goes stale
    winner = await acquire(MTGO, trigger=TRIGGER_SCHEDULED, store=store)
    await store.release(MTGO, zombie.run_id)  # late release from the dead run
    still_there = await store.read(MTGO)
    assert still_there is not None
    assert still_there.run_id == winner.run_id


# --------------------------------------------------------------------------- #
# Staleness (the SIGKILL story)
# --------------------------------------------------------------------------- #


async def test_stale_lock_does_not_block_a_new_run_forever(
    store: InMemoryLockStore, clock: _Clock
) -> None:
    """A killed process leaves a row behind; it must not wedge the scraper."""
    await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)

    # Still fresh: refused.
    clock.advance(60)
    with pytest.raises(ScrapeAlreadyRunning):
        await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)

    # Past the staleness window: taken over.
    clock.advance(200)
    taken = await acquire(MTGO, trigger=TRIGGER_SCHEDULED, store=store)
    assert taken.trigger == TRIGGER_SCHEDULED


async def test_stale_lock_reports_as_not_running(store: InMemoryLockStore, clock: _Clock) -> None:
    await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    clock.advance(1000)
    fields = run_status_fields(await store.read(MTGO))
    assert fields["is_running"] is False
    assert fields["running_since"] is None


async def test_heartbeat_keeps_a_long_run_alive(store: InMemoryLockStore, clock: _Clock) -> None:
    run = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    clock.advance(150)
    assert await store.heartbeat(MTGO, run.run_id) is True
    clock.advance(150)  # 300s since start, but only 150s since the heartbeat
    with pytest.raises(ScrapeAlreadyRunning):
        await acquire(MTGO, trigger=TRIGGER_SCHEDULED, store=store)


async def test_heartbeat_reports_false_after_takeover(
    store: InMemoryLockStore, clock: _Clock
) -> None:
    zombie = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    clock.advance(300)
    await acquire(MTGO, trigger=TRIGGER_SCHEDULED, store=store)
    assert await store.heartbeat(MTGO, zombie.run_id) is False


async def test_held_beats_the_heartbeat_while_the_scrape_runs(
    store: InMemoryLockStore, clock: _Clock
) -> None:
    run = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    async with held(run, store=store, heartbeat_seconds=0.01):
        clock.advance(1000)  # nothing else would keep this lock alive
        await asyncio.sleep(0.05)
        current = await store.read(MTGO)
        assert current is not None and current.is_live
    assert await store.read(MTGO) is None


# --------------------------------------------------------------------------- #
# running_since shape (consumed by #130)
# --------------------------------------------------------------------------- #


async def test_run_status_fields_for_an_active_run(store: InMemoryLockStore) -> None:
    run = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=store)
    fields = run_status_fields(await store.read(MTGO))
    assert fields["is_running"] is True
    assert fields["running_since"] == run.started_at
    assert fields["run_trigger"] == TRIGGER_MANUAL
    assert fields["run_id"] == run.run_id


async def test_run_status_fields_when_idle() -> None:
    assert run_status_fields(None) == {
        "is_running": False,
        "running_since": None,
        "run_id": None,
        "run_trigger": None,
        "last_heartbeat_at": None,
    }


async def test_scraper_health_endpoint_exposes_running_since(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_health(_session: Any, scraper_name: str) -> dict[str, Any]:
        return {"scraper_name": scraper_name, "is_broken": False, "consecutive_failures": 0}

    monkeypatch.setattr(analytics_main, "get_scraper_health_row", fake_health)

    resp = await admin_client.get("/analytics/admin/scraper-health?scraper_name=mtgo")
    assert resp.status_code == 200
    assert resp.json()["is_running"] is False
    assert resp.json()["running_since"] is None

    run = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=installed_store)
    resp = await admin_client.get("/analytics/admin/scraper-health?scraper_name=mtgo")
    body = resp.json()
    assert body["is_running"] is True
    assert datetime.fromisoformat(body["running_since"]) == run.started_at
    assert body["run_trigger"] == TRIGGER_MANUAL

    await installed_store.release(MTGO, run.run_id)
    body = (await admin_client.get("/analytics/admin/scraper-health?scraper_name=mtgo")).json()
    assert body["is_running"] is False
    assert body["running_since"] is None


# --------------------------------------------------------------------------- #
# Admin trigger endpoints
# --------------------------------------------------------------------------- #


async def test_manual_trigger_starts_a_run_and_frees_the_lock(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ran: list[bool] = []

    async def fake_scrape(_sm: Any) -> None:
        run = await installed_store.read(MTGO)
        ran.append(bool(run and run.is_live))

    monkeypatch.setattr(analytics_main, "run_mtgo_scrape", fake_scrape)

    resp = await admin_client.post("/analytics/admin/scrape-mtgo")
    assert resp.status_code == 202
    assert resp.json()["status"] == "scrape_started"
    assert ran == [True], "the background scrape must run under the lock"
    assert await installed_store.read(MTGO) is None


async def test_second_manual_trigger_is_rejected_with_409(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The double-click case: the second POST must not queue a duplicate."""
    calls: list[str] = []

    async def fake_scrape(_sm: Any) -> None:
        calls.append("ran")

    monkeypatch.setattr(analytics_main, "run_mtgo_scrape", fake_scrape)

    # A run is in flight (its background task has not finished yet).
    active = await acquire(MTGO, trigger=TRIGGER_MANUAL, store=installed_store)

    resp = await admin_client.post("/analytics/admin/scrape-mtgo")
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "scrape_already_running"
    assert body["scraper_name"] == "mtgo"
    assert body["running_since"] == active.started_at.isoformat()
    assert body["run_trigger"] == TRIGGER_MANUAL
    assert calls == [], "no duplicate scrape may start"


async def test_manual_trigger_rejected_while_the_scheduler_is_running(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def fake_scrape(_sm: Any) -> None:
        calls.append("ran")

    monkeypatch.setattr(analytics_main, "run_mtgo_scrape", fake_scrape)
    await acquire(MTGO, trigger=TRIGGER_SCHEDULED, store=installed_store)

    resp = await admin_client.post("/analytics/admin/scrape-mtgo")
    assert resp.status_code == 409
    assert resp.json()["run_trigger"] == TRIGGER_SCHEDULED
    assert calls == []


async def test_mtgtop8_trigger_has_its_own_lock(
    admin_client: httpx.AsyncClient,
    installed_store: InMemoryLockStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_scrape(_sm: Any) -> None:
        return None

    monkeypatch.setattr(analytics_main, "run_mtgtop8_scrape", fake_scrape)
    await acquire(MTGO, trigger=TRIGGER_MANUAL, store=installed_store)

    resp = await admin_client.post("/analytics/admin/scrape-mtgtop8")
    assert resp.status_code == 202

    resp = await admin_client.post("/analytics/admin/scrape-mtgtop8")
    assert resp.status_code == 202, "mtgtop8 is idle again once its own run finished"


# --------------------------------------------------------------------------- #
# Scheduler path
# --------------------------------------------------------------------------- #


async def test_scheduled_run_skips_when_a_manual_run_holds_the_lock(
    installed_store: InMemoryLockStore,
) -> None:
    calls: list[str] = []

    async def fake_scrape(_sm: Any) -> None:
        calls.append("ran")

    await acquire(MTGO, trigger=TRIGGER_MANUAL, store=installed_store)
    await analytics_main._run_scrape_if_idle(MTGO, fake_scrape, _fake_sessionmaker)
    assert calls == [], "the scheduler must not duplicate an active manual run"


async def test_scheduled_run_proceeds_when_idle(installed_store: InMemoryLockStore) -> None:
    calls: list[str] = []

    async def fake_scrape(_sm: Any) -> None:
        calls.append("ran")

    await analytics_main._run_scrape_if_idle(MTGO, fake_scrape, _fake_sessionmaker)
    assert calls == ["ran"]
    assert await installed_store.read(MTGO) is None


# --------------------------------------------------------------------------- #
# Losing the lease mid-run
# --------------------------------------------------------------------------- #


async def test_scrape_is_aborted_when_another_owner_takes_the_lock(
    store: InMemoryLockStore, clock: _Clock
) -> None:
    """A run whose heartbeat fell behind must stop, not scrape on unlocked
    next to the new owner."""
    cancelled = asyncio.Event()
    started = asyncio.Event()

    async def long_scrape() -> str:
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return "finished"

    async def steal() -> None:
        await started.wait()
        clock.advance(1000)  # our heartbeat is now hopelessly stale
        await acquire(MTGO, trigger=TRIGGER_SCHEDULED, store=store)

    thief = asyncio.create_task(steal())
    with pytest.raises(ScrapeLeaseLost):
        await run_locked(
            MTGO, long_scrape, trigger=TRIGGER_MANUAL, store=store, heartbeat_seconds=0.01
        )
    await thief
    assert cancelled.is_set(), "the scrape must be cancelled, not left running"

    # The new owner still holds the lock: the aborted run's release is
    # run_id-guarded and must not free somebody else's row.
    current = await store.read(MTGO)
    assert current is not None
    assert current.trigger == TRIGGER_SCHEDULED


async def test_lease_loss_does_not_crash_the_scheduler_tick(
    installed_store: InMemoryLockStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lost lease is an operational warning, not a crashed background loop."""

    async def boom(*_args: Any, **_kwargs: Any) -> None:
        raise ScrapeLeaseLost(
            MTGO, await acquire(MTGO, trigger=TRIGGER_MANUAL, store=installed_store)
        )

    monkeypatch.setattr(analytics_main, "run_scrape_locked", boom)

    async def fake_scrape(_sm: Any) -> None:
        return None

    await analytics_main._run_scrape_if_idle(MTGO, fake_scrape, _fake_sessionmaker)
