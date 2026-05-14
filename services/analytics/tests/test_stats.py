"""Stats endpoint tests.

The cross-schema queries against ``parser.matches`` / ``parser.games``
need a real Postgres to exercise; here we focus on handler/aggregation
behavior by overriding the DB-session dependency with a fake that
returns prefab rows. The aggregation logic itself (``_classify_match``
+ ``_summarize``) is exercised through the route so the assertions
also cover the wiring.
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
    out = tmp_path_factory.mktemp("analytics-jwt-keys")
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


def _patch_loader(monkeypatch: pytest.MonkeyPatch, matches: list[dict[str, Any]]) -> None:
    from analytics_service import stats as _stats

    async def fake_loader(_db: Any, _user_id: int) -> list[dict[str, Any]]:
        return matches

    monkeypatch.setattr(_stats, "_load_user_matches", fake_loader)

    # Disable Redis caching in tests so cached values don't leak between tests
    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(_stats, "_get_redis_or_none", _no_redis)


# ---------------------------------------------------------------------------
# /summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_empty_state(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _patch_loader(monkeypatch, [])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/summary")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["total_matches"] == 0
    assert body["wins"] == 0
    assert body["losses"] == 0
    assert body["draws"] == 0
    assert body["win_rate"] == 0.0
    assert body["recent_matches"] == []


@pytest.mark.asyncio
async def test_summary_counts_wins_losses_draws(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    m1 = uuid.uuid4()
    m2 = uuid.uuid4()
    m3 = uuid.uuid4()
    matches = [
        {  # win 2-1
            "id": m1,
            "format": "Modern",
            "players": ["alice", "bob"],
            "played_at": datetime(2026, 5, 9, 10, 0, tzinfo=UTC),
            "wins_by_player": {"alice": 2, "bob": 1},
        },
        {  # loss 0-2
            "id": m2,
            "format": "Modern",
            "players": ["alice", "carol"],
            "played_at": datetime(2026, 5, 8, 10, 0, tzinfo=UTC),
            "wins_by_player": {"carol": 2},
        },
        {  # draw 1-1
            "id": m3,
            "format": "Pioneer",
            "players": ["alice", "dan"],
            "played_at": datetime(2026, 5, 7, 10, 0, tzinfo=UTC),
            "wins_by_player": {"alice": 1, "dan": 1},
        },
    ]
    _patch_loader(monkeypatch, matches)
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/summary")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["total_matches"] == 3
    assert body["wins"] == 1
    assert body["losses"] == 1
    assert body["draws"] == 1
    # 1 win / (1 win + 1 loss) = 50%
    assert body["win_rate"] == 50.0
    assert len(body["recent_matches"]) == 3
    first = body["recent_matches"][0]
    assert first["match_id"] == str(m1)
    assert first["opponent"] == "bob"
    assert first["result"] == "W"
    assert first["format"] == "Modern"
    assert first["player_wins"] == 2
    assert first["player_losses"] == 1


@pytest.mark.asyncio
async def test_summary_unauth_returns_401(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/analytics/stats/summary")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# /by-format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_by_format_empty_state(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _patch_loader(monkeypatch, [])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/by-format")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_by_format_buckets_by_format(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    matches = [
        {
            "id": uuid.uuid4(),
            "format": "Modern",
            "players": ["alice", "bob"],
            "played_at": datetime(2026, 5, 9, tzinfo=UTC),
            "wins_by_player": {"alice": 2, "bob": 0},
        },
        {
            "id": uuid.uuid4(),
            "format": "Modern",
            "players": ["alice", "bob"],
            "played_at": datetime(2026, 5, 8, tzinfo=UTC),
            "wins_by_player": {"bob": 2},
        },
        {
            "id": uuid.uuid4(),
            "format": "Pioneer",
            "players": ["alice", "carol"],
            "played_at": datetime(2026, 5, 7, tzinfo=UTC),
            "wins_by_player": {"alice": 2, "carol": 1},
        },
    ]
    _patch_loader(monkeypatch, matches)
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/by-format")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2
    by_fmt = {row["format"]: row for row in rows}
    assert by_fmt["Modern"]["matches"] == 2
    assert by_fmt["Modern"]["wins"] == 1
    assert by_fmt["Modern"]["losses"] == 1
    assert by_fmt["Modern"]["win_rate"] == 50.0
    assert by_fmt["Pioneer"]["matches"] == 1
    assert by_fmt["Pioneer"]["wins"] == 1
    assert by_fmt["Pioneer"]["win_rate"] == 100.0


# ---------------------------------------------------------------------------
# /by-opponent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_by_opponent_empty_state(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _patch_loader(monkeypatch, [])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/by-opponent")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_by_opponent_buckets_by_opponent(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    matches = [
        {
            "id": uuid.uuid4(),
            "format": "Modern",
            "players": ["alice", "bob"],
            "played_at": datetime(2026, 5, 9, tzinfo=UTC),
            "wins_by_player": {"alice": 2, "bob": 0},
        },
        {
            "id": uuid.uuid4(),
            "format": "Modern",
            "players": ["alice", "bob"],
            "played_at": datetime(2026, 5, 8, tzinfo=UTC),
            "wins_by_player": {"bob": 2, "alice": 1},
        },
        {
            "id": uuid.uuid4(),
            "format": "Pioneer",
            "players": ["alice", "carol"],
            "played_at": datetime(2026, 5, 7, tzinfo=UTC),
            "wins_by_player": {"alice": 2},
        },
    ]
    _patch_loader(monkeypatch, matches)
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/by-opponent")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    rows = r.json()
    by_opp = {row["opponent"]: row for row in rows}
    assert by_opp["bob"]["matches"] == 2
    assert by_opp["bob"]["wins"] == 1
    assert by_opp["bob"]["losses"] == 1
    assert by_opp["bob"]["win_rate"] == 50.0
    assert by_opp["carol"]["matches"] == 1
    assert by_opp["carol"]["wins"] == 1
    assert by_opp["carol"]["win_rate"] == 100.0
