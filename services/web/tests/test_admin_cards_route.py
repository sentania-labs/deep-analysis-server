"""Tests for the /admin/cards admin route.

Bypasses browser auth via FastAPI dependency overrides and patches the
analytics client. Covers admin gating, the happy path (card-mirror status
render), the sync trigger redirect, and the analytics-outage banner.
"""

from __future__ import annotations

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


def _override_admin(user_id: int = 1, token: str = "admin-tok") -> Any:
    from web_service import deps as _deps

    fake_admin = _deps.BrowserUser(
        user_id=user_id,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token=token,
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_admin

    return _dep


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


def _sample_status() -> dict[str, Any]:
    return {
        "card_count": 31337,
        "last_sync_at": datetime(2026, 5, 9, 1, 0, tzinfo=UTC),
    }


@pytest.mark.asyncio
async def test_admin_cards_renders(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_status(_url: str, _token: str) -> Any:
        return _sample_status()

    monkeypatch.setattr(analytics_client, "admin_get_cards_status", fake_status)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/cards")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    text = r.text
    assert "31337" in text
    assert 'action="/admin/cards/sync"' in text
    assert "Sync started" not in text
    assert "MTGO scraper health" not in text


@pytest.mark.asyncio
async def test_admin_cards_shows_synced_banner(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_status(*_a: Any, **_kw: Any) -> Any:
        return _sample_status()

    monkeypatch.setattr(analytics_client, "admin_get_cards_status", fake_status)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/cards", params={"synced": 1})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Sync started" in r.text


@pytest.mark.asyncio
async def test_admin_cards_outage_banner_when_status_unavailable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom_status(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "admin_get_cards_status", boom_status)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/cards")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503
    assert "Analytics service unavailable" in r.text


@pytest.mark.asyncio
async def test_admin_cards_non_admin_403(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/admin/cards")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_cards_sync_redirects_to_synced_marker(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    triggered: dict[str, bool] = {}

    async def fake_trigger(_url: str, _token: str) -> bool:
        triggered["called"] = True
        return True

    monkeypatch.setattr(analytics_client, "admin_trigger_sync", fake_trigger)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post("/admin/cards/sync")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"] == "/admin/cards?synced=1"
    assert triggered.get("called") is True


@pytest.mark.asyncio
async def test_admin_cards_sync_non_admin_403(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.post("/admin/cards/sync")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403
