"""Web admin settings route tests (W3.6.3).

Covers the registration-mode UI surface at /admin/settings and the
form-POST handler at /admin/settings/registration-mode. The auth
service is faked through monkeypatched auth_client wrappers — we're
testing handler behavior + the UID=1-vs-other-admin UI split, not the
auth service itself (that lives in services/auth/tests).
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


def _sample_mode(
    mode: str = "invite_only",
    *,
    updated_by: int | None = None,
) -> Any:
    from web_service import auth_client

    return auth_client.RegistrationMode(
        mode=mode,
        updated_at=datetime(2026, 4, 26, 12, 0, tzinfo=UTC),
        updated_by_user_id=updated_by,
    )


# ---------------------------------------------------------------------------
# GET /admin/settings — render mode + correct UI for UID=1 vs others
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_settings_renders_for_root_admin_with_enabled_toggle(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_get(_url: str, _token: str) -> auth_client.RegistrationMode:
        return _sample_mode("invite_only")

    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_get)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Registration mode" in r.text
    assert "<strong>invite_only</strong>" in r.text
    # UID=1 → toggle is enabled (no `disabled` attr on the <select>)
    # and the Save submit is present.
    assert 'name="mode"' in r.text
    assert "disabled" not in r.text.split('name="mode"', 1)[1].split(">", 1)[0]
    assert "Save" in r.text


@pytest.mark.asyncio
async def test_get_settings_renders_disabled_toggle_for_non_root_admin(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_get(_url: str, _token: str) -> auth_client.RegistrationMode:
        return _sample_mode("open")

    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_get)
    dep, _ = _override_admin(user_id=2)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # Mode is still surfaced — read-only is the spec.
    assert "<strong>open</strong>" in r.text
    # Select is disabled and the lock tooltip is present somewhere on the page.
    select_attrs = r.text.split('name="mode"', 1)[1].split(">", 1)[0]
    assert "disabled" in select_attrs
    assert "UID=1" in r.text
    assert "original installer admin" in r.text
    # No Save button for non-root admins.
    assert "Save" not in r.text


@pytest.mark.asyncio
async def test_get_settings_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_settings_unauth_redirects(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/admin/settings")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_get_settings_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_get_registration_mode", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_get_settings_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_get_registration_mode", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_settings_renders_saved_banner(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_get(_url: str, _token: str) -> auth_client.RegistrationMode:
        return _sample_mode("open", updated_by=1)

    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_get)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/settings?saved=1")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Registration mode updated" in r.text


# ---------------------------------------------------------------------------
# POST /admin/settings/registration-mode — root admin happy path + errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_root_admin_success_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_set(
        _url: str, _token: str, mode: str
    ) -> tuple[auth_client.RegistrationMode | None, str | None]:
        captured["mode"] = mode
        return _sample_mode(mode, updated_by=1), None

    monkeypatch.setattr(auth_client, "admin_set_registration_mode", fake_set)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/registration-mode",
            data={"mode": "open"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/settings")
    assert "saved=1" in r.headers["location"]
    assert captured["mode"] == "open"


@pytest.mark.asyncio
async def test_post_non_root_admin_returns_inline_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_set(
        _url: str, _token: str, mode: str
    ) -> tuple[auth_client.RegistrationMode | None, str | None]:
        return None, "not_root_admin"

    async def fake_get(_url: str, _token: str) -> auth_client.RegistrationMode:
        return _sample_mode("invite_only")

    monkeypatch.setattr(auth_client, "admin_set_registration_mode", fake_set)
    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_get)
    dep, _ = _override_admin(user_id=2)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/registration-mode",
            data={"mode": "open"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403
    # Page still rendered with current value + lock-tooltip message.
    assert "UID=1" in r.text
    assert "<strong>invite_only</strong>" in r.text


@pytest.mark.asyncio
async def test_post_invalid_mode_returns_400(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_set(
        _url: str, _token: str, mode: str
    ) -> tuple[auth_client.RegistrationMode | None, str | None]:
        return None, "invalid_mode"

    async def fake_get(_url: str, _token: str) -> auth_client.RegistrationMode:
        return _sample_mode("invite_only")

    monkeypatch.setattr(auth_client, "admin_set_registration_mode", fake_set)
    monkeypatch.setattr(auth_client, "admin_get_registration_mode", fake_get)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/registration-mode",
            data={"mode": "garbage"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 400
    assert "Invalid registration mode" in r.text


@pytest.mark.asyncio
async def test_post_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_set_registration_mode", boom)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/registration-mode",
            data={"mode": "open"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_post_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_set_registration_mode", boom)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/registration-mode",
            data={"mode": "open"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_forbidden_for_non_admin(app_client: httpx.AsyncClient) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/settings/registration-mode",
            data={"mode": "open"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403
