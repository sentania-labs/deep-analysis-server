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
    # Sync button + form present
    assert 'action="/admin/cards/sync"' in text
    assert "Sync started" not in text  # not via ?synced=1
    # Scraper health section removed (lives on /admin/scrapers now)
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

    # Cards status failed -> 503.
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


@pytest.mark.asyncio
async def test_admin_cards_sync_conflict_redirects_to_running_marker(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 409 from analytics (sync already running) must not read as 'started'."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_trigger(_url: str, _token: str) -> bool:
        raise analytics_client.AnalyticsConflict(
            "analytics POST /admin/sync-cards returned 409",
            {"error": "sync_already_running", "job_name": "scryfall_sync"},
        )

    monkeypatch.setattr(analytics_client, "admin_trigger_sync", fake_trigger)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post("/admin/cards/sync")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"] == "/admin/cards?sync_running=1"


@pytest.mark.asyncio
async def test_admin_cards_shows_sync_running_banner(
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
        r = await app_client.get("/admin/cards", params={"sync_running": 1})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "already running" in r.text
    assert "Sync started" not in r.text


@pytest.mark.asyncio
async def test_admin_trigger_sync_raises_conflict_on_409(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client surfaces analytics' 409 as AnalyticsConflict, like the scrapers."""
    from web_service import analytics_client

    class _Resp:
        status_code = 409
        text = '{"error": "sync_already_running"}'

        def json(self) -> dict[str, Any]:
            return {"error": "sync_already_running", "job_name": "scryfall_sync"}

    async def fake_raw_request(*_a: Any, **_kw: Any) -> _Resp:
        return _Resp()

    monkeypatch.setattr(analytics_client, "raw_request", fake_raw_request)

    with pytest.raises(analytics_client.AnalyticsConflict) as caught:
        await analytics_client.admin_trigger_sync("http://analytics", "tok")
    assert caught.value.payload["error"] == "sync_already_running"
