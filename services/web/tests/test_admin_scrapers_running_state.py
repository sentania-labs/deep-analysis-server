"""Admin UI reflects an active scrape instead of inviting a double-click (#127).

The analytics API refuses a duplicate trigger with a 409. These tests
cover the other half of that promise: while a run holds the lock, the
pages that carry a "Scrape now" / "Run Now" button render it disabled
and say when the run started, so the interface does not offer an action
the API would reject.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import pytest_asyncio

RUNNING_SINCE = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


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


def _override_admin() -> Any:
    from web_service import deps as _deps

    admin = _deps.BrowserUser(
        user_id=1,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return admin

    return _dep


def _scraper(name: str, *, is_running: bool) -> dict[str, Any]:
    return {
        "scraper_name": name,
        "enabled": True,
        "interval_hours": 24,
        "last_run_at": None,
        "last_success_at": None,
        "consecutive_failures": 0,
        "is_broken": False,
        "last_error": None,
        "is_running": is_running,
        "running_since": RUNNING_SINCE if is_running else None,
        "run_trigger": "manual" if is_running else None,
    }


async def _get(
    app_client: httpx.AsyncClient, url: str, monkeypatch: pytest.MonkeyPatch, *, running: bool
) -> httpx.Response:
    from web_service import analytics_client, auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_scrapers(_url: str, _token: str) -> list[dict[str, Any]]:
        return [_scraper("mtgo", is_running=running), _scraper("mtgtop8", is_running=False)]

    async def fake_health(_url: str, _token: str) -> list[dict[str, Any]]:
        return [_scraper("mtgo", is_running=running), _scraper("mtgtop8", is_running=False)]

    async def fake_mode(_url: str, _token: str) -> Any:
        # Non-None so /admin/settings renders 200: the page falls back to
        # 503 only when every auth-side read failed, which is not what
        # these tests are about.
        return auth_client.RegistrationMode(
            mode="invite_only", updated_at=None, updated_by_user_id=None
        )

    monkeypatch.setattr(analytics_client, "admin_get_scrapers", fake_scrapers)
    monkeypatch.setattr(analytics_client, "admin_get_all_scraper_health", fake_health)
    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_mode)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        return await app_client.get(url)
    finally:
        _main.app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_scrapers_dashboard_disables_run_now_while_running(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = await _get(app_client, "/admin/scrapers", monkeypatch, running=True)
    assert r.status_code == 200
    body = r.text
    assert "Running..." in body
    assert "disabled" in body
    assert "2026-08-26 12:00" in body
    # The idle scraper keeps its working button.
    assert "/admin/scrapers/mtgtop8/trigger" in body
    assert "/admin/scrapers/mtgo/trigger" not in body


@pytest.mark.asyncio
async def test_scrapers_dashboard_offers_run_now_when_idle(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = await _get(app_client, "/admin/scrapers", monkeypatch, running=False)
    assert r.status_code == 200
    assert "/admin/scrapers/mtgo/trigger" in r.text
    assert "Running..." not in r.text


@pytest.mark.asyncio
async def test_settings_data_sources_row_shows_running_state(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = await _get(app_client, "/admin/settings", monkeypatch, running=True)
    assert r.status_code == 200
    body = r.text
    assert "RUNNING" in body
    assert "Running since 2026-08-26 12:00" in body
    assert 'action="/admin/settings/scrape-mtgo"' not in body
    # mtgtop8 is idle, so its trigger form is still rendered.
    assert 'action="/admin/settings/scrape-mtgtop8"' in body


@pytest.mark.asyncio
async def test_scrapers_dashboard_surfaces_the_already_running_error(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The trigger handler redirects here with ?error=...; the page must
    show it rather than swallowing the refusal."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_scrapers(_url: str, _token: str) -> list[dict[str, Any]]:
        return [_scraper("mtgo", is_running=True)]

    monkeypatch.setattr(analytics_client, "admin_get_scrapers", fake_scrapers)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/scrapers?error=mtgo+scrape+already+running")
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 200
    assert 'role="alert"' in r.text
    assert "mtgo scrape already running" in r.text


@pytest.mark.asyncio
async def test_scrapers_dashboard_trigger_redirects_on_409(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_trigger(_url: str, _token: str) -> bool:
        raise analytics_client.AnalyticsConflict("409", {})

    monkeypatch.setattr(analytics_client, "admin_trigger_mtgo_scrape", fake_trigger)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post("/admin/scrapers/mtgo/trigger")
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 303
    assert "error=mtgo+scrape+already+running" in r.headers["location"]


@pytest.mark.asyncio
async def test_settings_data_sources_row_offers_trigger_when_idle(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = await _get(app_client, "/admin/settings", monkeypatch, running=False)
    assert 'action="/admin/settings/scrape-mtgo"' in r.text


# ---------------------------------------------------------------------------
# analytics_client: the 409 branch and the running fields it parses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_raises_conflict_on_409(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import analytics_client, http_helper

    payload = {
        "error": "scrape_already_running",
        "scraper_name": "mtgo",
        "running_since": "2026-08-26T12:00:00+00:00",
        "run_trigger": "scheduled",
    }

    async def fake_raw(*_args: Any, **_kwargs: Any) -> httpx.Response:
        return httpx.Response(409, json=payload)

    monkeypatch.setattr(analytics_client, "raw_request", fake_raw)
    monkeypatch.setattr(http_helper, "raw_request", fake_raw, raising=False)

    with pytest.raises(analytics_client.AnalyticsConflict) as caught:
        await analytics_client.admin_trigger_mtgo_scrape("http://analytics", "tok")
    assert caught.value.payload["error"] == "scrape_already_running"
    assert caught.value.payload["run_trigger"] == "scheduled"


@pytest.mark.asyncio
async def test_client_parses_running_since_from_scraper_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client

    async def fake_request(*_args: Any, **_kwargs: Any) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "scrapers": [
                    {
                        "scraper_name": "mtgo",
                        "consecutive_failures": 0,
                        "is_broken": False,
                        "is_running": True,
                        "running_since": "2026-08-26T12:00:00Z",
                        "run_trigger": "manual",
                    }
                ]
            },
        )

    monkeypatch.setattr(analytics_client, "request", fake_request)
    healths = await analytics_client.admin_get_all_scraper_health("http://analytics", "tok")
    assert healths[0]["is_running"] is True
    assert healths[0]["running_since"] == RUNNING_SINCE
    assert healths[0]["run_trigger"] == "manual"
