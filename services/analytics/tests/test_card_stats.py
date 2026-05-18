"""Card stats and turn-data endpoint tests.

Overrides ``get_session`` with a fake session that returns prefab rows,
and ``require_user`` with a fake user dep. Tests exercise the handler
aggregation logic without a live Postgres.

v0.9.4: Updated to monkeypatch ``_load_card_appearances_auto`` for the
card stats endpoints since the SQL-level JSONB extraction is not
reproducible with the simple fake session.  Turn-data tests still use
the fake session directly (they don't touch the card appearance loader).
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
    out = tmp_path_factory.mktemp("analytics-jwt-keys-cardstats")
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


class _RowProxy:
    """Mimics SQLAlchemy Row for tuple-unpacking and indexing."""

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
# Card appearance test helpers
# ---------------------------------------------------------------------------


def _patch_card_loader(
    monkeypatch: pytest.MonkeyPatch,
    appearances: list[dict[str, Any]],
) -> None:
    """Monkeypatch _load_card_appearances_auto to return canned data."""
    from analytics_service import card_stats as _cs

    async def fake_loader(
        _db: Any,
        _user_id: int,
        _hero_name: str | None,
        card_name: str | None = None,
        format_filter: str | None = None,
        opponent: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        result = appearances
        if card_name:
            result = [a for a in result if a["card_name"].lower() == card_name.lower()]
        if format_filter:
            result = [a for a in result if (a.get("format") or "").lower() == format_filter.lower()]
        return result

    monkeypatch.setattr(_cs, "_load_card_appearances_auto", fake_loader)


def _patch_hero_name(
    monkeypatch: pytest.MonkeyPatch,
    hero_name: str | None,
) -> None:
    """Monkeypatch _resolve_hero_name in card_stats."""
    from analytics_service import card_stats as _cs

    async def fake_resolver(_db: Any, _user_id: int) -> str | None:
        return hero_name

    monkeypatch.setattr(_cs, "_resolve_hero_name", fake_resolver)


# ---------------------------------------------------------------------------
# GET /analytics/stats/cards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_card_stats_empty(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _patch_hero_name(monkeypatch, "alice")
    _patch_card_loader(monkeypatch, [])

    # Still need a fake session for the catalog.cards query (won't be called since no agg)
    session = _FakeSession(queue=[])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/cards")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["cards"] == []
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_card_stats_aggregates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    g1 = uuid.uuid4()
    g2 = uuid.uuid4()

    # Card appearances in the shape returned by the loader
    appearances = [
        {
            "game_id": g1,
            "winner": "alice",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Lightning Bolt",
            "first_turn": 3,
            "hero": "alice",
        },
        {
            "game_id": g1,
            "winner": "alice",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Mountain",
            "first_turn": 3,
            "hero": "alice",
        },
        {
            "game_id": g2,
            "winner": "bob",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Lightning Bolt",
            "first_turn": 5,
            "hero": "alice",
        },
    ]
    _patch_hero_name(monkeypatch, "alice")
    _patch_card_loader(monkeypatch, appearances)

    # Fake session only needed for the catalog.cards metadata query
    session = _FakeSession(
        queue=[
            [
                ("Lightning Bolt", "Instant", "{R}"),
                ("Mountain", "Basic Land — Mountain", None),
            ],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/cards")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    by_name = {c["name"]: c for c in body["cards"]}
    bolt = by_name["Lightning Bolt"]
    assert bolt["cast_count"] == 2
    assert bolt["win_rate"] == 50.0
    assert bolt["avg_cast_turn"] == 4.0  # (3 + 5) / 2
    assert bolt["type_line"] == "Instant"
    assert bolt["mana_cost"] == "{R}"
    mountain = by_name["Mountain"]
    assert mountain["cast_count"] == 1
    assert mountain["win_rate"] == 100.0


@pytest.mark.asyncio
async def test_card_stats_pagination(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    g1 = uuid.uuid4()

    appearances = [
        {
            "game_id": g1,
            "winner": "alice",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Card A",
            "first_turn": 2,
            "hero": "alice",
        },
        {
            "game_id": g1,
            "winner": "alice",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Card B",
            "first_turn": 2,
            "hero": "alice",
        },
        {
            "game_id": g1,
            "winner": "alice",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Card C",
            "first_turn": 2,
            "hero": "alice",
        },
    ]
    _patch_hero_name(monkeypatch, "alice")
    _patch_card_loader(monkeypatch, appearances)

    # catalog.cards — none found
    session = _FakeSession(queue=[[]])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/cards", params={"per_page": 2, "page": 1})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["cards"]) == 2
    assert body["per_page"] == 2
    assert body["page"] == 1


# ---------------------------------------------------------------------------
# GET /analytics/stats/cards/{card_name}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_card_detail(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    g1 = uuid.uuid4()
    g2 = uuid.uuid4()

    appearances = [
        {
            "game_id": g1,
            "winner": "alice",
            "players": ["alice", "bob"],
            "format": "Modern",
            "card_name": "Lightning Bolt",
            "first_turn": 3,
            "hero": "alice",
        },
        {
            "game_id": g2,
            "winner": "bob",
            "players": ["alice", "bob"],
            "format": "Pioneer",
            "card_name": "Lightning Bolt",
            "first_turn": 5,
            "hero": "alice",
        },
    ]
    _patch_hero_name(monkeypatch, "alice")
    _patch_card_loader(monkeypatch, appearances)

    session = _FakeSession(queue=[])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/cards/Lightning Bolt")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Lightning Bolt"
    assert body["total_games"] == 2
    assert body["wins"] == 1
    assert body["win_rate"] == 50.0
    assert body["avg_cast_turn"] == 4.0
    assert len(body["by_format"]) == 2


@pytest.mark.asyncio
async def test_card_detail_not_found(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _patch_hero_name(monkeypatch, "alice")
    _patch_card_loader(monkeypatch, [])

    session = _FakeSession(queue=[])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get("/analytics/stats/cards/Nonexistent Card")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "card_not_found"


# ---------------------------------------------------------------------------
# GET /analytics/stats/matches/{match_id}/games/{game_number}/turns
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_game_turns(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    match_id = uuid.uuid4()
    game_id = uuid.uuid4()

    session = _FakeSession(
        queue=[
            # match ownership check
            [(match_id,)],
            # game lookup
            [(game_id,)],
            # game_states rows: (turn_number, active_player, player_states, stack)
            [
                (
                    1,
                    "alice",
                    {
                        "alice": {"life": 20, "zones": {"hand": ["Mountain"]}, "mana_pool": {}},
                        "bob": {"life": 20, "zones": {"hand": []}, "mana_pool": {}},
                    },
                    [],
                ),
                (
                    2,
                    "bob",
                    {
                        "alice": {"life": 20, "zones": {"hand": []}, "mana_pool": {}},
                        "bob": {"life": 18, "zones": {"hand": ["Island"]}, "mana_pool": {}},
                    },
                    ["Counterspell"],
                ),
            ],
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get(f"/analytics/stats/matches/{match_id}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    assert body[0]["turn_number"] == 1
    assert body[0]["active_player"] == "alice"
    assert body[0]["players"]["alice"]["life"] == 20
    assert body[0]["stack"] == []
    assert body[1]["turn_number"] == 2
    assert body[1]["stack"] == ["Counterspell"]


@pytest.mark.asyncio
async def test_game_turns_match_not_found(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    match_id = uuid.uuid4()
    session = _FakeSession(queue=[[]])  # match not found
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get(f"/analytics/stats/matches/{match_id}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "match_not_found"


@pytest.mark.asyncio
async def test_game_turns_game_not_found(app_client: httpx.AsyncClient) -> None:
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    match_id = uuid.uuid4()
    session = _FakeSession(
        queue=[
            [(match_id,)],  # match found
            [],  # game not found
        ]
    )
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    _main.app.dependency_overrides[_db.get_session] = _override_session(session)
    try:
        r = await app_client.get(f"/analytics/stats/matches/{match_id}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "game_not_found"


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_card_stats_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/analytics/stats/cards")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_game_turns_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get(f"/analytics/stats/matches/{uuid.uuid4()}/games/1/turns")
    assert r.status_code == 401
