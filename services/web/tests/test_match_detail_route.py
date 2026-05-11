"""Tests for the /matches/{match_id} detail route.

Bypasses browser auth via FastAPI dependency overrides and patches the
analytics client. Covers the happy path (renders metadata + games),
the 404 path (analytics returned None), the analytics-outage 503, and
the overall W/L/D computation from the games list.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    from web_service import deps as _deps
    from web_service import main as _main
    from web_service import settings as _settings

    _settings._settings = None
    _deps.reset_verifier()

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _override_user(user_id: int = 42, token: str = "user-tok") -> Any:
    from web_service import deps as _deps

    fake_user = _deps.BrowserUser(
        user_id=user_id,
        email="alice@example.com",
        role="user",
        must_change_password=False,
        scope=None,
        token=token,
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_user

    return _dep


def _sample_match(
    *,
    match_id: str,
    games_won_by_uploader: int = 2,
    games_won_by_opponent: int = 1,
) -> Any:
    from web_service import analytics_client

    games: list[Any] = []
    n = 0
    for _ in range(games_won_by_uploader):
        n += 1
        games.append(analytics_client.GameItem(game_number=n, winner="alice", turns=7))
    for _ in range(games_won_by_opponent):
        n += 1
        games.append(analytics_client.GameItem(game_number=n, winner="bob", turns=10))
    return analytics_client.MatchDetail(
        match_id=match_id,
        format_="Modern",
        players=["alice", "bob"],
        played_at=datetime(2026, 5, 9, 12, 0, tzinfo=UTC),
        games=games,
    )


@pytest.mark.asyncio
async def test_match_detail_renders(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_detail(_url: str, _token: str, mid: str) -> Any:
        assert mid == match_id
        return _sample_match(match_id=match_id)

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    text = r.text
    # Title uses first 8 chars of the match id.
    assert match_id[:8] in text
    assert "Modern" in text
    assert "alice" in text
    assert "bob" in text
    # Three games rendered (2W, 1L) → overall W.
    assert "result-win" in text


@pytest.mark.asyncio
async def test_match_detail_overall_loss(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_detail(_url: str, _token: str, _mid: str) -> Any:
        return _sample_match(
            match_id=match_id,
            games_won_by_uploader=0,
            games_won_by_opponent=2,
        )

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "result-loss" in r.text


@pytest.mark.asyncio
async def test_match_detail_404_when_analytics_returns_none(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_detail(*_a: Any, **_kw: Any) -> Any:
        return None

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{uuid.uuid4()}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert "Match not found" in r.text


@pytest.mark.asyncio
async def test_match_detail_503_when_analytics_unavailable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "get_match_detail", boom)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{uuid.uuid4()}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_match_detail_malformed_id_returns_422(app_client: httpx.AsyncClient) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/matches/not-a-uuid")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 422


@pytest.mark.asyncio
async def test_match_detail_unauth_redirects_to_login(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get(f"/matches/{uuid.uuid4()}")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")
