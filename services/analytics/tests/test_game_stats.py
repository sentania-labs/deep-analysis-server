"""Game-level stats endpoint tests.

Overrides ``get_session`` with a fake session that returns prefab rows,
and ``require_user`` with a fake user dep. Tests exercise the handler
aggregation logic without a live Postgres.
"""

from __future__ import annotations

import os
import uuid
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
    out = tmp_path_factory.mktemp("analytics-jwt-keys-gamestats")
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


# ---------------------------------------------------------------------------
# Fake DB layer
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[Any, ...]]:
        return list(self._rows)

    def scalar_one_or_none(self) -> Any:
        if not self._rows:
            return None
        return self._rows[0][0] if isinstance(self._rows[0], tuple) else self._rows[0]


class _FakeSession:
    """Returns canned row sets in queue order."""

    def __init__(self, *, queue: list[list[tuple[Any, ...]]]) -> None:
        self._queue = list(queue)
        self.calls: list[dict[str, Any]] = []

    async def execute(self, _stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        self.calls.append(dict(params or {}))
        rows = self._queue.pop(0) if self._queue else []
        return _FakeResult(rows)


def _override_session(session: _FakeSession) -> Any:
    async def _dep() -> AsyncIterator[Any]:
        yield session

    return _dep


# ---------------------------------------------------------------------------
# Play/draw tests
# ---------------------------------------------------------------------------

# Helper: make a game row tuple matching the _load_games_with_context query:
# (game_number, winner, on_play, play_first, opening_hand_sizes, players, format, game_id)


def _game_row(
    game_number: int,
    winner: str | None,
    on_play: bool | None,
    play_first: str | None = None,
    opening_hand_sizes: dict | None = None,
    players: list | None = None,
    fmt: str = "Modern",
    game_id: Any | None = None,
) -> tuple:
    return (
        game_number,
        winner,
        on_play,
        play_first,
        opening_hand_sizes or {},
        players or ["alice", "bob"],
        fmt,
        game_id or uuid.uuid4(),
    )


@pytest.mark.asyncio
async def test_play_draw_empty(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(
        queue=[
            [],  # games query
            [],  # mtgo_usernames query
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/play-draw")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["on_play"]["total"] == 0
    assert body["on_draw"]["total"] == 0


@pytest.mark.asyncio
async def test_play_draw_splits(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(
        queue=[
            # games: alice on play wins, alice on draw loses, alice on play loses
            [
                _game_row(1, "alice", True),
                _game_row(2, "bob", False),
                _game_row(1, "bob", True),
            ],
            # mtgo_usernames
            [(["alice"],)],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/play-draw")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["on_play"]["total"] == 2
    assert body["on_play"]["wins"] == 1
    assert body["on_play"]["win_rate"] == 50.0
    assert body["on_draw"]["total"] == 1
    assert body["on_draw"]["wins"] == 0
    assert body["on_draw"]["win_rate"] == 0.0


# ---------------------------------------------------------------------------
# Preboard / postboard tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preboard_postboard(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(
        queue=[
            # games: game 1 win, game 2 loss, game 3 win
            [
                _game_row(1, "alice", True),
                _game_row(2, "bob", False),
                _game_row(3, "alice", True),
            ],
            # mtgo_usernames
            [(["alice"],)],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/preboard-postboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["preboard"]["total"] == 1
    assert body["preboard"]["wins"] == 1
    assert body["preboard"]["win_rate"] == 100.0
    assert body["postboard"]["total"] == 2
    assert body["postboard"]["wins"] == 1
    assert body["postboard"]["win_rate"] == 50.0


# ---------------------------------------------------------------------------
# Mulligan tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mulligans(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    session = _FakeSession(
        queue=[
            [
                _game_row(1, "alice", True, opening_hand_sizes={"alice": 7, "bob": 7}),
                _game_row(2, "bob", False, opening_hand_sizes={"alice": 6, "bob": 7}),
                _game_row(1, "alice", True, opening_hand_sizes={"alice": 7, "bob": 6}),
            ],
            # mtgo_usernames
            [(["alice"],)],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/mulligans")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    # Sorted descending by hand size: 7, 6
    assert len(body) == 2
    assert body[0]["hand_size"] == 7
    assert body[0]["total"] == 2
    assert body[0]["wins"] == 2
    assert body[0]["win_rate"] == 100.0
    assert body[1]["hand_size"] == 6
    assert body[1]["total"] == 1
    assert body[1]["wins"] == 0
    assert body[1]["win_rate"] == 0.0


# ---------------------------------------------------------------------------
# Game-length tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_game_length_buckets(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    g1 = uuid.uuid4()
    g2 = uuid.uuid4()
    g3 = uuid.uuid4()

    session = _FakeSession(
        queue=[
            # mtgo_usernames
            [(["alice"],)],
            # game-length query: (game_id, winner, players, max_turn)
            [
                (g1, "alice", ["alice", "bob"], 5),
                (g2, "bob", ["alice", "bob"], 11),
                (g3, "alice", ["alice", "bob"], 14),
            ],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/game-length")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    by_bucket = {b["bucket"]: b for b in body}
    assert by_bucket["4-6"]["total"] == 1
    assert by_bucket["4-6"]["wins"] == 1
    assert by_bucket["4-6"]["losses"] == 0
    assert by_bucket["10-12"]["total"] == 1
    assert by_bucket["10-12"]["wins"] == 0
    assert by_bucket["10-12"]["losses"] == 1
    assert by_bucket["13+"]["total"] == 1
    assert by_bucket["13+"]["wins"] == 1


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_play_draw_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/analytics/stats/play-draw")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_mulligans_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/analytics/stats/mulligans")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_game_length_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/analytics/stats/game-length")
    assert r.status_code == 401
