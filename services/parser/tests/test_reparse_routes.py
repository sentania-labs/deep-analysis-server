"""Parser-side tests for the user self-service reparse endpoint.

POST /parser/me/reparse enforces a 1-hour per-user cooldown by writing
the last-reparse timestamp into auth.server_settings.  These tests
mock the clock (parser_service.reparse._now) so we don't have to sleep
an hour to exercise the cooldown-expired path.

The pure unit tests (without DB) cover endpoint wiring + the rate-limit
decision; the DB-backed test exercises the actual SQL round-trip
against a real Postgres (gated on DA_TEST_DATABASE_URL like the rest
of the parser DB tests — see conftest.py).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

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


@pytest.mark.asyncio
async def test_self_service_reparse_succeeds_when_no_prior_record(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First call returns 200 and stamps the cooldown timestamp."""
    from parser_service import reparse as _reparse

    async def fake_get_last(_db: AsyncSession, _uid: int) -> datetime | None:
        return None

    stamped: dict[str, Any] = {}

    async def fake_set_last(_db: AsyncSession, uid: int, when: datetime) -> None:
        stamped["uid"] = uid
        stamped["when"] = when

    async def fake_delete(
        _db: AsyncSession,
        _uid: int,
        _after: Any,
        _before: Any,
        *,
        agent_id: str | None = None,
    ) -> int:
        return 5

    monkeypatch.setattr(_reparse, "_get_last_reparse", fake_get_last)
    monkeypatch.setattr(_reparse, "_set_last_reparse", fake_set_last)
    monkeypatch.setattr(_reparse, "_delete_matches_for_user", fake_delete)

    # Bypass the real DB session — the fakes above don't touch the
    # session, so a no-op stand-in is fine.
    class _NoopSession:
        async def commit(self) -> None:
            return None

    from parser_service import db as _db
    from parser_service import main as _main

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
    assert stamped["uid"] == 123
    assert stamped["when"].tzinfo is not None


@pytest.mark.asyncio
async def test_self_service_reparse_rate_limited_inside_cooldown(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Second call inside the 1-hour window returns 429 with retry_at."""
    from parser_service import reparse as _reparse

    now = datetime(2026, 5, 24, 10, 0, 0, tzinfo=UTC)
    # Last reparse was 30 minutes ago — half the cooldown window.
    last = now - timedelta(seconds=1800)

    monkeypatch.setattr(_reparse, "_now", lambda: now)

    async def fake_get_last(_db: AsyncSession, _uid: int) -> datetime | None:
        return last

    called: dict[str, bool] = {"delete": False, "set": False}

    async def fake_delete(*_a: Any, **_kw: Any) -> int:
        called["delete"] = True
        return 0

    async def fake_set_last(*_a: Any, **_kw: Any) -> None:
        called["set"] = True

    monkeypatch.setattr(_reparse, "_get_last_reparse", fake_get_last)
    monkeypatch.setattr(_reparse, "_delete_matches_for_user", fake_delete)
    monkeypatch.setattr(_reparse, "_set_last_reparse", fake_set_last)

    class _NoopSession:
        async def commit(self) -> None:
            return None

    from parser_service import db as _db
    from parser_service import main as _main

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
    # Half-window passed → ~1800s remaining.
    assert 1700 <= body["detail"]["retry_after_seconds"] <= 1800
    # retry_at = last + 3600s.
    expected_retry_at = (last + timedelta(seconds=3600)).isoformat()
    assert body["detail"]["retry_at"] == expected_retry_at
    # Neither the delete nor the stamp ran when we hit the rate limit.
    assert called["delete"] is False
    assert called["set"] is False


@pytest.mark.asyncio
async def test_self_service_reparse_allowed_after_cooldown(
    app_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once the 1-hour window passes, a second call succeeds and the
    timestamp gets bumped to *now*."""
    from parser_service import reparse as _reparse

    now = datetime(2026, 5, 24, 10, 0, 0, tzinfo=UTC)
    # Last reparse was 65 minutes ago — past the cooldown.
    last = now - timedelta(seconds=3900)

    monkeypatch.setattr(_reparse, "_now", lambda: now)

    async def fake_get_last(_db: AsyncSession, _uid: int) -> datetime | None:
        return last

    stamped: dict[str, Any] = {}

    async def fake_set_last(_db: AsyncSession, uid: int, when: datetime) -> None:
        stamped["uid"] = uid
        stamped["when"] = when

    async def fake_delete(*_a: Any, **_kw: Any) -> int:
        return 7

    monkeypatch.setattr(_reparse, "_get_last_reparse", fake_get_last)
    monkeypatch.setattr(_reparse, "_set_last_reparse", fake_set_last)
    monkeypatch.setattr(_reparse, "_delete_matches_for_user", fake_delete)

    class _NoopSession:
        async def commit(self) -> None:
            return None

    from parser_service import db as _db
    from parser_service import main as _main

    async def _fake_session() -> AsyncIterator[Any]:
        yield _NoopSession()

    _main.app.dependency_overrides[_db.get_session] = _fake_session
    _override_user_dep(user_id=42)
    try:
        r = await app_client.post("/parser/me/reparse")
    finally:
        _clear_overrides()

    assert r.status_code == 200
    assert r.json() == {"deleted_count": 7}
    # The stamp got bumped to `now`, not left at `last`.
    assert stamped["when"] == now


@pytest.mark.asyncio
async def test_self_service_reparse_requires_auth(
    app_client: AsyncClient,
) -> None:
    """No JWT → 401."""
    r = await app_client.post("/parser/me/reparse")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# DB-backed helper round-trip — needs DA_TEST_DATABASE_URL
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def auth_settings_session(
    parser_session: AsyncSession,
) -> AsyncIterator[AsyncSession]:
    """parser_session + a guaranteed-empty auth.server_settings table.

    The parser conftest only creates parser/analytics schemas, but
    _get_last_reparse / _set_last_reparse target auth.server_settings.
    Bootstrap a minimal-compatible schema here so the helpers work
    end-to-end without dragging in the auth service's full Alembic head.
    """
    await parser_session.execute(text("CREATE SCHEMA IF NOT EXISTS auth"))
    await parser_session.execute(
        text(
            "CREATE TABLE IF NOT EXISTS auth.server_settings ("
            "  key VARCHAR(64) PRIMARY KEY,"
            "  value JSONB NOT NULL,"
            "  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            "  updated_by_user_id INTEGER NULL"
            ")"
        )
    )
    await parser_session.execute(text("TRUNCATE auth.server_settings"))
    await parser_session.commit()
    yield parser_session


@pytest.mark.asyncio
async def test_last_reparse_helpers_round_trip(
    auth_settings_session: AsyncSession,
) -> None:
    """_set_last_reparse(now) then _get_last_reparse() returns the same UTC dt."""
    from parser_service import reparse as _reparse

    user_id = 12345
    # Round to seconds — the round-trip goes through ISO string and back,
    # which doesn't preserve sub-microsecond precision in all backends.
    when = datetime.now(UTC).replace(microsecond=0)

    # Initially nothing recorded.
    assert await _reparse._get_last_reparse(auth_settings_session, user_id) is None

    await _reparse._set_last_reparse(auth_settings_session, user_id, when)
    await auth_settings_session.commit()

    got = await _reparse._get_last_reparse(auth_settings_session, user_id)
    assert got == when

    # UPSERT path — write a fresh timestamp, read it back.
    later = when + timedelta(seconds=3600)
    await _reparse._set_last_reparse(auth_settings_session, user_id, later)
    await auth_settings_session.commit()

    got2 = await _reparse._get_last_reparse(auth_settings_session, user_id)
    assert got2 == later
