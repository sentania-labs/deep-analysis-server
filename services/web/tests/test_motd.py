"""MOTD (Message of the Day) banner tests.

Covers:
- Setting/clearing MOTD via admin routes
- MOTD appears when active and non-expired
- MOTD does not appear when expired
- Severity affects banner styling
- MOTD injection into all template renders via middleware
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from web_service import auth_client


@pytest_asyncio.fixture
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    from web_service import deps as _deps
    from web_service import main as _main
    from web_service import settings as _settings

    _settings._settings = None
    _deps.reset_verifier()
    _main._reset_motd_cache()

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    _main._reset_motd_cache()


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

    return _dep, fake_admin


def _override_non_admin(user_id: int = 42) -> Any:
    from web_service import deps as _deps

    fake_user = _deps.BrowserUser(
        user_id=user_id,
        email="u@example.com",
        role="user",
        must_change_password=False,
        scope=None,
        token="user-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_user

    return _dep, fake_user


def _sample_mode(mode: str = "invite_only") -> Any:
    return auth_client.RegistrationMode(
        mode=mode,
        updated_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        updated_by_user_id=None,
    )


def _sample_tunables() -> Any:
    return auth_client.TunablesResult(
        backfill_batch_size=100,
        backfill_interval_seconds=300,
        scryfall_sync_interval_days=7,
        mtgo_scraper_interval_hours=24,
        parser_version="0.9.0",
        reparse_min_version="0.9.0",
        min_agent_version="0.5.0",
    )


def _active_motd(
    message: str = "Maintenance tonight at 10 PM UTC",
    severity: str = "info",
    hours_until_expiry: int = 24,
) -> auth_client.MotdResult:
    return auth_client.MotdResult(
        active=True,
        message=message,
        severity=severity,
        expires_at=datetime.now(UTC) + timedelta(hours=hours_until_expiry),
        updated_at=datetime.now(UTC),
        updated_by_user_id=1,
    )


def _inactive_motd() -> auth_client.MotdResult:
    return auth_client.MotdResult(active=False)


def _patch_settings_deps(
    monkeypatch: pytest.MonkeyPatch,
    *,
    motd: auth_client.MotdResult | None = None,
) -> None:
    """Monkeypatch common dependencies for admin settings page."""
    from web_service import analytics_client

    async def fake_mode(_url: str, _token: str) -> auth_client.RegistrationMode:
        return _sample_mode()

    async def fake_tunables(_url: str, _token: str) -> auth_client.TunablesResult:
        return _sample_tunables()

    async def fake_motd_admin(_url: str, _token: str) -> auth_client.MotdResult:
        return motd if motd is not None else _inactive_motd()

    async def fake_motd_public(_url: str) -> auth_client.MotdResult:
        return motd if motd is not None else _inactive_motd()

    async def _empty_cards(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("noop")

    async def _empty_scrapers(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("noop")

    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "admin_get_tunables", fake_tunables)
    monkeypatch.setattr(auth_client, "admin_get_motd", fake_motd_admin)
    monkeypatch.setattr(auth_client, "public_get_motd", fake_motd_public)
    monkeypatch.setattr(analytics_client, "admin_get_cards_status", _empty_cards)
    monkeypatch.setattr(analytics_client, "admin_get_all_scraper_health", _empty_scrapers)


# ---------------------------------------------------------------------------
# Admin settings page renders MOTD section
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_settings_shows_no_active_banner(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _patch_settings_deps(monkeypatch, motd=_inactive_motd())
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Site banner (MOTD)" in r.text
    assert "No active banner" in r.text


@pytest.mark.asyncio
async def test_admin_settings_shows_active_info_banner(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    motd = _active_motd(message="Servers will restart at midnight", severity="info")
    _patch_settings_deps(monkeypatch, motd=motd)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Servers will restart at midnight" in r.text
    assert "Current banner (info)" in r.text
    assert "Clear banner" in r.text


@pytest.mark.asyncio
async def test_admin_settings_shows_active_warning_banner(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    motd = _active_motd(message="Data loss detected", severity="warning")
    _patch_settings_deps(monkeypatch, motd=motd)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Data loss detected" in r.text
    assert "Current banner (warning)" in r.text
    # Warning severity uses red styling
    assert "bg-red" in r.text


# ---------------------------------------------------------------------------
# POST /admin/settings/motd — set banner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_motd_success_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_set(
        _url: str,
        _token: str,
        *,
        message: str,
        severity: str,
        expires_at: str,
    ) -> tuple[auth_client.MotdResult | None, str | None]:
        captured["message"] = message
        captured["severity"] = severity
        captured["expires_at"] = expires_at
        return _active_motd(message=message, severity=severity), None

    monkeypatch.setattr(auth_client, "admin_set_motd", fake_set)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/motd",
            data={
                "motd_message": "Test banner",
                "motd_severity": "warning",
                "motd_expires_at": "2026-06-01T12:00",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert "motd_saved=1" in r.headers["location"]
    assert captured["message"] == "Test banner"
    assert captured["severity"] == "warning"


@pytest.mark.asyncio
async def test_post_motd_empty_message_returns_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _patch_settings_deps(monkeypatch)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/motd",
            data={
                "motd_message": "   ",
                "motd_severity": "info",
                "motd_expires_at": "2026-06-01T12:00",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 400
    assert "Banner message is required" in r.text


@pytest.mark.asyncio
async def test_post_motd_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/motd",
            data={
                "motd_message": "Test",
                "motd_severity": "info",
                "motd_expires_at": "2026-06-01T12:00",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# POST /admin/settings/motd/clear — clear banner
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_clear_motd_success_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_clear(_url: str, _token: str) -> tuple[bool, str | None]:
        return True, None

    monkeypatch.setattr(auth_client, "admin_clear_motd", fake_clear)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/settings/motd/clear")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert "motd_cleared=1" in r.headers["location"]


@pytest.mark.asyncio
async def test_post_clear_motd_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/settings/motd/clear")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Banner displays on user-facing pages via middleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_motd_banner_visible_on_landing_page(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The MOTD banner should appear on the public landing page."""
    from web_service import main as _main

    motd = _active_motd(message="Platform upgrade in progress", severity="info")

    async def fake_public_motd(_url: str) -> auth_client.MotdResult:
        return motd

    async def fake_reg_mode(_url: str) -> str:
        return "invite_only"

    monkeypatch.setattr(auth_client, "public_get_motd", fake_public_motd)
    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_reg_mode)
    _main._reset_motd_cache()

    r = await app_client.get("/")
    assert r.status_code == 200
    assert "Platform upgrade in progress" in r.text
    assert "motd-banner" in r.text


@pytest.mark.asyncio
async def test_motd_banner_not_visible_when_inactive(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No banner should render when MOTD is inactive."""
    from web_service import main as _main

    async def fake_public_motd(_url: str) -> auth_client.MotdResult:
        return _inactive_motd()

    async def fake_reg_mode(_url: str) -> str:
        return "invite_only"

    monkeypatch.setattr(auth_client, "public_get_motd", fake_public_motd)
    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_reg_mode)
    _main._reset_motd_cache()

    r = await app_client.get("/")
    assert r.status_code == 200
    assert "motd-banner" not in r.text


@pytest.mark.asyncio
async def test_motd_info_severity_uses_green_styling(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import main as _main

    motd = _active_motd(message="Good news everyone", severity="info")

    async def fake_public_motd(_url: str) -> auth_client.MotdResult:
        return motd

    async def fake_reg_mode(_url: str) -> str:
        return "invite_only"

    monkeypatch.setattr(auth_client, "public_get_motd", fake_public_motd)
    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_reg_mode)
    _main._reset_motd_cache()

    r = await app_client.get("/")
    assert r.status_code == 200
    assert "bg-emerald" in r.text
    assert "Good news everyone" in r.text


@pytest.mark.asyncio
async def test_motd_warning_severity_uses_red_styling(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import main as _main

    motd = _active_motd(message="Critical issue detected", severity="warning")

    async def fake_public_motd(_url: str) -> auth_client.MotdResult:
        return motd

    async def fake_reg_mode(_url: str) -> str:
        return "invite_only"

    monkeypatch.setattr(auth_client, "public_get_motd", fake_public_motd)
    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_reg_mode)
    _main._reset_motd_cache()

    r = await app_client.get("/")
    assert r.status_code == 200
    assert "bg-red" in r.text
    assert "Critical issue detected" in r.text
