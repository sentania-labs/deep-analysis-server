"""Parser-side tests for the user self-service reparse endpoint.

POST /parser/me/reparse enforces a 1-hour per-user cooldown via an
atomic CAS UPSERT against ``parser.user_reparse_cooldown``. These
tests cover the rate-limit decision (mocked clock + a stub for the
CAS so we can drive both gate-open and gate-closed paths without a
DB), plus a DB-backed suite that exercises the actual SQL — including
the concurrent-requests case where two callers race for the same slot.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Pure-unit tests — endpoint wiring + rate-limit decision (no DB)
# ---------------------------------------------------------------------------


def _stub_env() -> None:
    """Minimum env vars to import parser_service.main without booting it."""
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    os.environ.setdefault("DA_SERVICE_NAME", "parser")
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://stub:stub@localhost/stub")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    os.environ.setdefault("DA_JWT_PUBLIC_KEY_PATH", str(repo_root / ".nonexistent-jwt-pub"))
    os.environ.setdefault("DA_PARSER_RAW_PATH", str(repo_root / ".nonexistent-raw"))


@pytest_asyncio.fixture
async def app_client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    _stub_env()
    from parser_service import main as _main
    from parser_service import settings as _settings

    _settings.reset_settings()
    _main.reset_consumer()

    async def _noop() -> None:
        return None

    monkeypatch.setattr(_main, "_start_consumer", _noop)
    monkeypatch.setattr(_main, "_stop_consumer", _noop)

    transport = ASGITransport(app=_main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _override_user_dep(user_id: int = 42) -> None:
    from parser_service import deps as _deps
    from parser_service import main as _main

    async def _dep() -> _deps.AuthenticatedUser:
        return _deps.AuthenticatedUser(user_id=user_id, role="user")

    _main.app.dependency_overrides[_deps.require_user] = _dep


def _clear_overrides() -> None:
    from parser_service import main as _main

    _main.app.dependency_overrides.clear()


class _NoopSession:
    async def commit(self) -> None:
        return None


@pytest.mark.asyncio
async def test_self_service_reparse_succeeds_when_slot_acquired(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the CAS reports the slot was acquired, the delete runs."""
    from parser_service import db as _db
    from parser_service import main as _main
    from parser_service import reparse as _reparse

    now = datetime(2026, 5, 24, 10, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(_reparse, "_now", lambda: now)

    cas_calls: dict[str, Any] = {}

    async def fake_cas(
        _db: AsyncSession, uid: int, when: datetime, cooldown: int
    ) -> tuple[bool, datetime]:
        cas_calls["uid"] = uid
        cas_calls["when"] = when
        cas_calls["cooldown"] = cooldown
        return True, when

    async def fake_delete(
        _db: AsyncSession,
        _uid: int,
        _after: Any,
        _before: Any,
        *,
        agent_id: str | None = None,
    ) -> int:
        return 5

    monkeypatch.setattr(_reparse, "_try_acquire_reparse_slot", fake_cas)
    monkeypatch.setattr(_reparse, "_delete_matches_for_user", fake_delete)

    async def _fake_session() -> AsyncIterator[Any]:
        yield _NoopSession()

    _main.app.dependency_overrides[_db.get_session] = _fake_session
    _override_user_dep(user_id=123)
    try:
        r = await app_client.post("/parser/me/reparse")
    finally:
        _clear_overrides()

    assert r.status_code == 200
    assert r.json() == {"deleted_count": 5}
    assert cas_calls["uid"] == 123
    assert cas_calls["when"] == now
    assert cas_calls["cooldown"] == 3600


@pytest.mark.asyncio
async def test_self_service_reparse_rate_limited_when_slot_held(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the CAS reports the slot is held, the route returns 429."""
    from parser_service import db as _db
    from parser_service import main as _main
    from parser_service import reparse as _reparse

    now = datetime(2026, 5, 24, 10, 0, 0, tzinfo=UTC)
    last = now - timedelta(seconds=1800)  # 30 min ago — still inside window
    monkeypatch.setattr(_reparse, "_now", lambda: now)

    async def fake_cas(*_a: Any, **_kw: Any) -> tuple[bool, datetime]:
        return False, last

    called: dict[str, bool] = {"delete": False}

    async def fake_delete(*_a: Any, **_kw: Any) -> int:
        called["delete"] = True
        return 0

    monkeypatch.setattr(_reparse, "_try_acquire_reparse_slot", fake_cas)
    monkeypatch.setattr(_reparse, "_delete_matches_for_user", fake_delete)

    async def _fake_session() -> AsyncIterator[Any]:
        yield _NoopSession()

    _main.app.dependency_overrides[_db.get_session] = _fake_session
    _override_user_dep(user_id=42)
    try:
        r = await app_client.post("/parser/me/reparse")
    finally:
        _clear_overrides()

    assert r.status_code == 429
    body = r.json()
    assert body["detail"]["error"] == "rate_limited"
    assert 1700 <= body["detail"]["retry_after_seconds"] <= 1800
    expected_retry_at = (last + timedelta(seconds=3600)).isoformat()
    assert body["detail"]["retry_at"] == expected_retry_at
    assert called["delete"] is False


@pytest.mark.asyncio
async def test_self_service_reparse_requires_auth(
    app_client: AsyncClient,
) -> None:
    """No JWT → 401."""
    r = await app_client.post("/parser/me/reparse")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# DB-backed CAS tests — needs DA_TEST_DATABASE_URL
#
# These exercise the real SQL against parser.user_reparse_cooldown and
# confirm:
#   - fresh user (no row) → acquired=True, row inserted
#   - existing stale row → acquired=True, row updated
#   - existing fresh row → acquired=False, returns existing stamp
#   - concurrent same-user calls → exactly one wins
#   - cross-user calls → both succeed (no spurious contention)
#   - the migration runs without any auth-schema grants (sanity)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def cooldown_session(
    parser_session: AsyncSession,
) -> AsyncIterator[AsyncSession]:
    """parser_session + a guaranteed-empty parser.user_reparse_cooldown table."""
    await parser_session.execute(
        text(
            "CREATE TABLE IF NOT EXISTS parser.user_reparse_cooldown ("
            "  user_id INTEGER PRIMARY KEY,"
            "  last_reparse_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        )
    )
    await parser_session.execute(text("TRUNCATE parser.user_reparse_cooldown"))
    await parser_session.commit()
    yield parser_session


@pytest.mark.asyncio
async def test_cas_inserts_when_no_prior_row(cooldown_session: AsyncSession) -> None:
    """Fresh user: row doesn't exist → CAS acquires, INSERTs new row."""
    from parser_service import reparse as _reparse

    now = datetime.now(UTC).replace(microsecond=0)
    acquired, last = await _reparse._try_acquire_reparse_slot(cooldown_session, 1001, now, 3600)
    await cooldown_session.commit()

    assert acquired is True
    assert last == now

    row = (
        await cooldown_session.execute(
            text("SELECT last_reparse_at FROM parser.user_reparse_cooldown WHERE user_id = :u"),
            {"u": 1001},
        )
    ).scalar_one()
    assert row == now


@pytest.mark.asyncio
async def test_cas_blocks_inside_cooldown(cooldown_session: AsyncSession) -> None:
    """Existing fresh row: CAS denies, returns the existing stamp."""
    from parser_service import reparse as _reparse

    base = datetime.now(UTC).replace(microsecond=0)
    # Seed an existing row 30 minutes old — half the cooldown window.
    await cooldown_session.execute(
        text(
            "INSERT INTO parser.user_reparse_cooldown (user_id, last_reparse_at) VALUES (:u, :ts)"
        ),
        {"u": 1002, "ts": base - timedelta(seconds=1800)},
    )
    await cooldown_session.commit()

    acquired, last = await _reparse._try_acquire_reparse_slot(cooldown_session, 1002, base, 3600)
    await cooldown_session.commit()

    assert acquired is False
    assert last == base - timedelta(seconds=1800)

    # Existing row stamp must not have been bumped.
    row = (
        await cooldown_session.execute(
            text("SELECT last_reparse_at FROM parser.user_reparse_cooldown WHERE user_id = :u"),
            {"u": 1002},
        )
    ).scalar_one()
    assert row == base - timedelta(seconds=1800)


@pytest.mark.asyncio
async def test_cas_allows_after_cooldown_expires(cooldown_session: AsyncSession) -> None:
    """Existing stale row (>1h old): CAS acquires, UPDATEs stamp to now."""
    from parser_service import reparse as _reparse

    now = datetime.now(UTC).replace(microsecond=0)
    stale = now - timedelta(seconds=3900)  # 65 min ago

    await cooldown_session.execute(
        text(
            "INSERT INTO parser.user_reparse_cooldown (user_id, last_reparse_at) VALUES (:u, :ts)"
        ),
        {"u": 1003, "ts": stale},
    )
    await cooldown_session.commit()

    acquired, last = await _reparse._try_acquire_reparse_slot(cooldown_session, 1003, now, 3600)
    await cooldown_session.commit()

    assert acquired is True
    assert last == now

    row = (
        await cooldown_session.execute(
            text("SELECT last_reparse_at FROM parser.user_reparse_cooldown WHERE user_id = :u"),
            {"u": 1003},
        )
    ).scalar_one()
    assert row == now


@pytest.mark.asyncio
async def test_cas_isolates_users(cooldown_session: AsyncSession) -> None:
    """User A's cooldown does not block user B from acquiring."""
    from parser_service import reparse as _reparse

    now = datetime.now(UTC).replace(microsecond=0)

    a_ok, _ = await _reparse._try_acquire_reparse_slot(cooldown_session, 2001, now, 3600)
    b_ok, _ = await _reparse._try_acquire_reparse_slot(cooldown_session, 2002, now, 3600)
    await cooldown_session.commit()

    assert a_ok is True
    assert b_ok is True

    # And the second attempt for user A *is* blocked.
    a_again, _ = await _reparse._try_acquire_reparse_slot(cooldown_session, 2001, now, 3600)
    await cooldown_session.commit()
    assert a_again is False


@pytest.mark.asyncio
async def test_cas_atomic_concurrent_callers(cooldown_session: AsyncSession) -> None:
    """Two concurrent same-user attempts: exactly one wins.

    Uses two independent AsyncSessions on the same engine so each call
    runs in its own transaction — the only correct way to exercise the
    INSERT/UPDATE row-lock serialization. A single shared session
    would just queue statements behind one transaction and never race.
    """
    from parser_service import reparse as _reparse

    url = os.environ.get("DA_TEST_DATABASE_URL")
    assert url, "DA_TEST_DATABASE_URL required for this test"

    now = datetime.now(UTC).replace(microsecond=0)
    engine = create_async_engine(url, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)

    async def _attempt() -> tuple[bool, datetime]:
        async with sm() as session:
            try:
                acquired, last = await _reparse._try_acquire_reparse_slot(session, 3001, now, 3600)
                await session.commit()
                return acquired, last
            except Exception:
                await session.rollback()
                raise

    try:
        results = await asyncio.gather(_attempt(), _attempt())
    finally:
        await engine.dispose()

    winners = [r for r in results if r[0]]
    losers = [r for r in results if not r[0]]
    assert len(winners) == 1
    assert len(losers) == 1
    # The loser's reported stamp equals the winner's `now`.
    assert losers[0][1] == winners[0][1] == now


@pytest.mark.asyncio
async def test_cas_does_not_touch_auth_schema(cooldown_session: AsyncSession) -> None:
    """Sanity: a fresh CAS call writes to parser only, not auth.

    The whole point of moving this cooldown out of auth.server_settings
    is that the parser DB role doesn't (and shouldn't) have grants on
    auth. We verify by asserting the parser table has a row after the
    call, and that no auth.server_settings entry was created for the
    legacy ``user_reparse_last:`` key.
    """
    from parser_service import reparse as _reparse

    # If the legacy table doesn't exist in this test DB, that's fine —
    # the CAS path shouldn't be reading it. We create it deliberately
    # empty so we can prove the new code path leaves it alone even
    # when present.
    await cooldown_session.execute(text("CREATE SCHEMA IF NOT EXISTS auth"))
    await cooldown_session.execute(
        text(
            "CREATE TABLE IF NOT EXISTS auth.server_settings ("
            "  key VARCHAR(64) PRIMARY KEY,"
            "  value JSONB NOT NULL,"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_by_user_id INTEGER NULL"
            ")"
        )
    )
    await cooldown_session.execute(text("TRUNCATE auth.server_settings"))
    await cooldown_session.commit()

    now = datetime.now(UTC).replace(microsecond=0)
    acquired, _ = await _reparse._try_acquire_reparse_slot(cooldown_session, 4001, now, 3600)
    await cooldown_session.commit()
    assert acquired is True

    # parser table has the row.
    parser_row = (
        await cooldown_session.execute(
            text("SELECT 1 FROM parser.user_reparse_cooldown WHERE user_id = :u"),
            {"u": 4001},
        )
    ).scalar_one_or_none()
    assert parser_row == 1

    # auth.server_settings still empty — no legacy key written.
    legacy = (
        await cooldown_session.execute(
            text("SELECT count(*) FROM auth.server_settings WHERE key LIKE 'user_reparse_last:%'")
        )
    ).scalar_one()
    assert legacy == 0
