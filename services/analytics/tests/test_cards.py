"""Card search endpoint tests.

The handler does direct SQL via ``db.execute(text(...))`` — we override
the ``get_session`` dep with a fake session that records the query and
returns prefab rows so we can exercise the blank-query fast path, a
matching search, and an empty-result search without a live Postgres.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys-cards")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(pub_pem)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    yield pub_path


@pytest_asyncio.fixture
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    from analytics_service import main as _main

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _override_user(user_id: int = 7) -> Any:
    from analytics_service import deps as _deps

    fake = _deps.AuthenticatedUser(user_id=user_id, role="user")

    async def _dep() -> _deps.AuthenticatedUser:
        return fake

    return _dep


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _FakeSession:
    """Captures execute calls; returns canned row sets in order."""

    def __init__(self, *, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows
        self.calls: list[dict[str, Any]] = []

    async def execute(self, _stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        self.calls.append(dict(params or {}))
        return _FakeResult(self._rows)


def _override_session(session: _FakeSession) -> Any:
    async def _dep() -> AsyncIterator[Any]:
        yield session

    return _dep


@pytest.mark.asyncio
async def test_cards_blank_query_returns_empty_list_without_hitting_db(
    app_client: httpx.AsyncClient,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(rows=[("should-not-appear", None, None, None, None, None)])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/cards", params={"q": "   "})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert r.json() == []
    # Blank query short-circuits without an execute() call.
    assert session.calls == []


@pytest.mark.asyncio
async def test_cards_returns_matches(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(
        rows=[
            (
                "Lightning Bolt",
                "{R}",
                "Instant",
                "Lightning Bolt deals 3 damage to any target.",
                "https://example/lb.jpg",
                "lea",
            ),
            (
                "Lightning Strike",
                "{1}{R}",
                "Instant",
                "Lightning Strike deals 3 damage to any target.",
                None,
                "thb",
            ),
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/cards", params={"q": "Lightning"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    assert body[0]["name"] == "Lightning Bolt"
    assert body[0]["mana_cost"] == "{R}"
    assert body[0]["image_uri"] == "https://example/lb.jpg"
    assert body[1]["image_uri"] is None
    # Confirm the ILIKE pattern was assembled with wildcards.
    assert session.calls[0]["pattern"] == "%Lightning%"
    assert session.calls[0]["limit"] == 20


@pytest.mark.asyncio
async def test_cards_no_matches_returns_empty_list(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(rows=[])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/cards", params={"q": "zzznosuchcard"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_cards_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/analytics/cards", params={"q": "Bolt"})
    assert r.status_code == 401
