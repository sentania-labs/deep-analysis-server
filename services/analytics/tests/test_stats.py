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

    async def fake_loader(
        _db: Any,
        _user_id: int,
        *,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        return matches

    monkeypatch.setattr(_stats, "_load_user_matches", fake_loader)

    # Disable Redis caching in tests so cached values don't leak between tests
    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(_stats, "_get_redis_or_none", _no_redis)


def _patch_loader_date_aware(
    monkeypatch: pytest.MonkeyPatch,
    matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Like _patch_loader but records date_from/date_to calls.

    Returns a mutable list that the fake appends call records to.
    """
    from analytics_service import stats as _stats

    calls: list[dict[str, Any]] = []

    async def fake_loader(
        _db: Any,
        _user_id: int,
        *,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        calls.append({"date_from": date_from, "date_to": date_to})
        return matches

    monkeypatch.setattr(_stats, "_load_user_matches", fake_loader)

    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(_stats, "_get_redis_or_none", _no_redis)
    return calls


def _match_dict(
    match_id: uuid.UUID,
    fmt: str,
    players: list[str],
    played_at: datetime,
    wins_by_player: dict[str, int],
    hero_player_name: str | None = None,
) -> dict[str, Any]:
    """Build a match dict in the shape returned by _load_user_matches."""
    return {
        "id": match_id,
        "format": fmt,
        "players": players,
        "played_at": played_at,
        "wins_by_player": wins_by_player,
        "hero_player_name": hero_player_name or (players[0] if players else None),
    }


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
        _match_dict(
            m1,
            "Modern",
            ["alice", "bob"],
            datetime(2026, 5, 9, 10, 0, tzinfo=UTC),
            {"alice": 2, "bob": 1},
        ),
        _match_dict(
            m2, "Modern", ["alice", "carol"], datetime(2026, 5, 8, 10, 0, tzinfo=UTC), {"carol": 2}
        ),
        _match_dict(
            m3,
            "Pioneer",
            ["alice", "dan"],
            datetime(2026, 5, 7, 10, 0, tzinfo=UTC),
            {"alice": 1, "dan": 1},
        ),
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
        _match_dict(
            uuid.uuid4(),
            "Modern",
            ["alice", "bob"],
            datetime(2026, 5, 9, tzinfo=UTC),
            {"alice": 2, "bob": 0},
        ),
        _match_dict(
            uuid.uuid4(), "Modern", ["alice", "bob"], datetime(2026, 5, 8, tzinfo=UTC), {"bob": 2}
        ),
        _match_dict(
            uuid.uuid4(),
            "Pioneer",
            ["alice", "carol"],
            datetime(2026, 5, 7, tzinfo=UTC),
            {"alice": 2, "carol": 1},
        ),
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
        _match_dict(
            uuid.uuid4(),
            "Modern",
            ["alice", "bob"],
            datetime(2026, 5, 9, tzinfo=UTC),
            {"alice": 2, "bob": 0},
        ),
        _match_dict(
            uuid.uuid4(),
            "Modern",
            ["alice", "bob"],
            datetime(2026, 5, 8, tzinfo=UTC),
            {"bob": 2, "alice": 1},
        ),
        _match_dict(
            uuid.uuid4(),
            "Pioneer",
            ["alice", "carol"],
            datetime(2026, 5, 7, tzinfo=UTC),
            {"alice": 2},
        ),
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


# ---------------------------------------------------------------------------
# /summary and /by-format with date_from / date_to
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_threads_date_params(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """date_from and date_to query params are forwarded to _load_user_matches."""
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    calls = _patch_loader_date_aware(monkeypatch, [])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get(
            "/analytics/stats/summary",
            params={"date_from": "2026-05-01", "date_to": "2026-05-10"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert len(calls) == 1
    assert calls[0]["date_from"] == "2026-05-01"
    assert calls[0]["date_to"] == "2026-05-10"


@pytest.mark.asyncio
async def test_summary_no_date_params_passes_none(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without date params, _load_user_matches receives None."""
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    calls = _patch_loader_date_aware(monkeypatch, [])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/summary")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert len(calls) == 1
    assert calls[0]["date_from"] is None
    assert calls[0]["date_to"] is None


@pytest.mark.asyncio
async def test_by_format_threads_date_params(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """date_from and date_to query params are forwarded through by-format."""
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    calls = _patch_loader_date_aware(monkeypatch, [])
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get(
            "/analytics/stats/by-format",
            params={"date_from": "2026-05-01", "date_to": "2026-05-15"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert len(calls) == 1
    assert calls[0]["date_from"] == "2026-05-01"
    assert calls[0]["date_to"] == "2026-05-15"


# ---------------------------------------------------------------------------
# Cache key differentiation with date params
# ---------------------------------------------------------------------------


def test_cache_key_differs_with_date_params() -> None:
    """Cache keys for date-filtered vs unfiltered requests must differ."""
    from common.cache import cache_key as ck

    key_no_date = ck(7, "summary")
    key_with_date = ck(7, "summary", date_from="2026-05-01", date_to="2026-05-10")
    key_different_date = ck(7, "summary", date_from="2026-04-01", date_to="2026-04-30")

    assert key_no_date != key_with_date
    assert key_with_date != key_different_date
    # None values should not affect the key (stripped by cache_key)
    key_none = ck(7, "summary", date_from=None, date_to=None)
    assert key_none == key_no_date
