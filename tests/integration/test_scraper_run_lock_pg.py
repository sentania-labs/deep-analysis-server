"""The scraper run lock against a real Postgres (#127).

The unit tests in ``services/analytics/tests/test_scraper_run_lock.py``
prove the lock's behaviour through an in-memory store. This module
proves the SQL that actually ships: the ``ON CONFLICT ... WHERE`` arm
that makes acquisition atomic, the run_id-guarded release, and the
staleness window that keeps a SIGKILLed run from wedging the scraper.

Skipped unless ``DA_DATABASE_URL`` (async driver) is set; CI sets it and
runs ``alembic upgrade head`` before pytest, so reaching these tests
means migration 031 applied.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from analytics_service.scraper_lock import (
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    PostgresLockStore,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

SCRAPER = "pytest-lock"

#: Short enough to keep the suite quick, long enough that a loaded CI
#: runner cannot age a live lock mid-test and turn a pass into a flake.
STALE_AFTER = 5.0


def _async_url() -> str | None:
    return os.environ.get("DA_DATABASE_URL") or os.environ.get("DA_TEST_DATABASE_URL")


@pytest.fixture
async def store() -> AsyncIterator[PostgresLockStore]:
    url = _async_url()
    if not url:
        pytest.skip("DA_DATABASE_URL not set, skipping lock round-trip")
    engine = create_async_engine(url, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as session:
        await session.execute(
            text("DELETE FROM analytics.scraper_runs WHERE scraper_name = :n"), {"n": SCRAPER}
        )
        await session.commit()
    try:
        yield PostgresLockStore(sm, stale_after_seconds=STALE_AFTER)
    finally:
        async with sm() as session:
            await session.execute(
                text("DELETE FROM analytics.scraper_runs WHERE scraper_name = :n"), {"n": SCRAPER}
            )
            await session.commit()
        await engine.dispose()


async def _acquire(store: PostgresLockStore, run_id: str, trigger: str = TRIGGER_MANUAL) -> Any:
    return await store.try_acquire(SCRAPER, run_id=run_id, trigger=trigger, owner="pytest")


async def test_first_acquire_wins_second_is_refused(store: PostgresLockStore) -> None:
    assert await _acquire(store, "run-1") is not None
    assert await _acquire(store, "run-2") is None


async def test_concurrent_acquires_have_exactly_one_winner(store: PostgresLockStore) -> None:
    """The ON CONFLICT arm is the whole point: only one row survives."""
    results = await asyncio.gather(*(_acquire(store, f"race-{i}") for i in range(8)))
    assert sum(1 for r in results if r is not None) == 1


async def test_release_frees_the_lock(store: PostgresLockStore) -> None:
    await _acquire(store, "run-1")
    await store.release(SCRAPER, "run-1")
    assert await store.read(SCRAPER) is None
    assert await _acquire(store, "run-2") is not None


async def test_release_by_a_stale_owner_is_a_no_op(store: PostgresLockStore) -> None:
    await _acquire(store, "zombie")
    await asyncio.sleep(STALE_AFTER + 0.5)  # zombie's heartbeat goes stale
    assert await _acquire(store, "winner", TRIGGER_SCHEDULED) is not None
    await store.release(SCRAPER, "zombie")  # late release from the dead run
    current = await store.read(SCRAPER)
    assert current is not None
    assert current.run_id == "winner"


async def test_stale_lock_is_taken_over(store: PostgresLockStore) -> None:
    """The SIGKILL case: no finally ran, the row stayed, nobody is wedged."""
    await _acquire(store, "killed")
    assert await _acquire(store, "next") is None
    await asyncio.sleep(STALE_AFTER + 0.5)
    taken = await _acquire(store, "next")
    assert taken is not None
    assert taken.run_id == "next"


async def test_heartbeat_refreshes_and_is_run_id_guarded(store: PostgresLockStore) -> None:
    await _acquire(store, "run-1")
    await asyncio.sleep(STALE_AFTER * 0.7)
    assert await store.heartbeat(SCRAPER, "run-1") is True
    await asyncio.sleep(STALE_AFTER * 0.7)
    # Past the window since acquire, but not since the heartbeat: still live.
    assert await _acquire(store, "run-2") is None
    assert await store.heartbeat(SCRAPER, "someone-else") is False


async def test_read_reports_liveness_and_running_since(store: PostgresLockStore) -> None:
    acquired = await _acquire(store, "run-1")
    assert acquired is not None
    live = await store.read(SCRAPER)
    assert live is not None
    assert live.is_live is True
    assert live.trigger == TRIGGER_MANUAL
    assert live.started_at == acquired.started_at

    await asyncio.sleep(STALE_AFTER + 0.5)
    stale = await store.read(SCRAPER)
    assert stale is not None
    assert stale.is_live is False
