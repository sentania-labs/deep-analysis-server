"""Match detail endpoint tests.

The handler does two direct SQL queries: the match lookup (with the
``WHERE user_id = :user_id`` ownership filter) and the games-with-turns
join. We override ``get_session`` with a fake session that returns
canned row sets in order, so we can verify the ownership filter,
404 paths, and games aggregation without a live Postgres.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys-matches")
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


class _RowProxy:
    """Mimics SQLAlchemy Row: supports tuple-unpacking AND .one_or_none()."""

    def __init__(self, row: tuple[Any, ...]) -> None:
        self._row = row

    def __iter__(self) -> Any:
        return iter(self._row)

    def __len__(self) -> int:
        return len(self._row)

    def __getitem__(self, idx: int) -> Any:
        return self._row[idx]


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[_RowProxy]:
        return [_RowProxy(r) for r in self._rows]

    def one_or_none(self) -> _RowProxy | None:
        if not self._rows:
            return None
        return _RowProxy(self._rows[0])


class _FakeSession:
    """Records execute() calls and pops results from a queue."""

    def __init__(self, *, queue: list[list[tuple[Any, ...]]]) -> None:
        self._queue = queue
        self.calls: list[dict[str, Any]] = []

    async def execute(self, _stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        self.calls.append(dict(params or {}))
        rows = self._queue.pop(0) if self._queue else []
        return _FakeResult(rows)


def _override_session(session: _FakeSession) -> Any:
    async def _dep() -> AsyncIterator[Any]:
        yield session

    return _dep


@pytest.mark.asyncio
async def test_match_detail_returns_match_with_games(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    match_id = uuid.uuid4()
    game_1_id = uuid.uuid4()
    game_2_id = uuid.uuid4()
    played_at = datetime(2026, 5, 9, 12, 30, tzinfo=UTC)
    session = _FakeSession(
        queue=[
            # match row
            [(match_id, "Modern", ["alice", "bob"], played_at)],
            # games rows: (game_id, game_number, winner, turns)
            [
                (game_1_id, 1, "alice", 8),
                (game_2_id, 2, "bob", 11),
            ],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user(user_id=7)
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get(f"/analytics/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["match_id"] == str(match_id)
    assert body["format"] == "Modern"
    assert body["players"] == ["alice", "bob"]
    assert len(body["games"]) == 2
    assert body["games"][0]["game_number"] == 1
    assert body["games"][0]["winner"] == "alice"
    assert body["games"][0]["turns"] == 8
    assert body["games"][1]["turns"] == 11
    # Ownership filter is applied: the match query received both
    # match_id and user_id parameters.
    first_call = session.calls[0]
    assert first_call["match_id"] == match_id
    assert first_call["user_id"] == 7


@pytest.mark.asyncio
async def test_match_detail_404_when_not_found_or_not_owned(
    app_client: httpx.AsyncClient,
) -> None:
    """Empty match-row result yields a 404.

    The handler's WHERE clause filters by both ``id`` and ``user_id``,
    so a not-owned match returns zero rows — same shape as not-found.
    Testing the empty-rows path covers both cases.
    """
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    match_id = uuid.uuid4()
    session = _FakeSession(queue=[[]])  # no match row
    _main.app.dependency_overrides[_deps.require_user] = _override_user(user_id=999)
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get(f"/analytics/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "match_not_found"


@pytest.mark.asyncio
async def test_match_detail_handles_missing_turns_gracefully(
    app_client: httpx.AsyncClient,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    match_id = uuid.uuid4()
    game_id = uuid.uuid4()
    session = _FakeSession(
        queue=[
            [(match_id, None, ["alice", "bob"], None)],
            # turns column is NULL when the parser didn't store game states
            [(game_id, 1, "alice", None)],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user(user_id=7)
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get(f"/analytics/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["games"][0]["turns"] is None
    assert body["format"] is None


@pytest.mark.asyncio
async def test_match_detail_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get(f"/analytics/matches/{uuid.uuid4()}")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_match_detail_malformed_id_returns_422(app_client: httpx.AsyncClient) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/matches/not-a-uuid")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 422
