"""Admin sessions land on /admin/users, not /dashboard or /profile.

W3.6 sub-item 1 — admin is purely administrative. The web layer
hides self-service routes from admin browsers and routes them
straight to the admin panel landing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
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


def _override_admin() -> Any:
    from web_service import deps as _deps

    fake = _deps.BrowserUser(
        user_id=1,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return fake

    return _dep


def _override_user() -> Any:
    from web_service import deps as _deps

    fake = _deps.BrowserUser(
        user_id=42,
        email="u@example.com",
        role="user",
        must_change_password=False,
        scope=None,
        token="user-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return fake

    return _dep


# ---------------------------------------------------------------------------
# /dashboard — admins bounce to /admin/users; users see the dashboard.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_admin_redirects_to_admin_panel(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"


@pytest.mark.asyncio
async def test_dashboard_user_renders(app_client: httpx.AsyncClient) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # User dashboard still shows self-service tabs.
    assert "/profile" in r.text
    assert "/profile/agents" in r.text


@pytest.mark.asyncio
async def test_dashboard_admin_shell_has_no_profile_links(
    app_client: httpx.AsyncClient,
) -> None:
    """Even if a stale path renders the dashboard for an admin (via a
    cached response or future code change), the shell template must
    not advertise /profile or /profile/agents.

    Renders the template directly with role=admin to guard the
    template itself, separate from the route-level redirect.
    """
    from web_service import main as _main

    rendered = _main.templates.get_template("dashboard.html").render(
        request=None,
        user={
            "user_id": 1,
            "email": "admin@local",
            "role": "admin",
        },
    )
    assert 'href="/profile"' not in rendered
    assert 'href="/profile/agents"' not in rendered
    assert 'href="/admin/users"' in rendered


# ---------------------------------------------------------------------------
# /profile* — admins bounce to /admin/users; mutation calls never reach auth.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_profile_admin_redirects_to_admin_panel(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/profile")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"


@pytest.mark.asyncio
async def test_profile_edit_form_admin_redirects_to_admin_panel(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/profile/edit")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"


@pytest.mark.asyncio
async def test_profile_edit_post_admin_redirects_without_calling_auth(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    called = False

    async def fake_update_me(*_a: Any, **_kw: Any) -> auth_client.UpdateMeResult:
        nonlocal called
        called = True
        return auth_client.UpdateMeResult(ok=True)

    monkeypatch.setattr(auth_client, "update_me", fake_update_me)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post("/profile/edit", data={"email": "x@example.com"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"
    assert called is False


@pytest.mark.asyncio
async def test_profile_agents_admin_redirects_to_admin_panel(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/profile/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"


@pytest.mark.asyncio
async def test_profile_agents_revoke_admin_redirects_without_calling_auth(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uuid

    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    called = False

    async def fake_revoke(*_a: Any, **_kw: Any) -> tuple[bool, str | None]:
        nonlocal called
        called = True
        return True, None

    monkeypatch.setattr(auth_client, "revoke_my_agent", fake_revoke)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post(f"/profile/agents/{uuid.uuid4()}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"
    assert called is False


# ---------------------------------------------------------------------------
# /login — admin token lands on /admin/users; user token lands on /dashboard.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_admin_lands_on_admin_panel(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import main as _main

    async def fake_login(_url: str, _email: str, _password: str) -> auth_client.LoginResult:
        return auth_client.LoginResult(
            access_token="admin.jwt",
            refresh_token="r",
            expires_in=900,
            must_change_password=False,
        )

    def fake_role(token: str) -> str | None:
        return "admin" if token == "admin.jwt" else None

    monkeypatch.setattr(auth_client, "login", fake_login)
    monkeypatch.setattr(_main, "_role_from_token", fake_role)

    r = await app_client.post(
        "/login",
        data={"email": "admin@local", "password": "pw"},
    )

    assert r.status_code == 303
    assert r.headers["location"] == "/admin/users"


@pytest.mark.asyncio
async def test_login_user_lands_on_dashboard(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import main as _main

    async def fake_login(_url: str, _email: str, _password: str) -> auth_client.LoginResult:
        return auth_client.LoginResult(
            access_token="user.jwt",
            refresh_token="r",
            expires_in=900,
            must_change_password=False,
        )

    def fake_role(_token: str) -> str | None:
        return "user"

    monkeypatch.setattr(auth_client, "login", fake_login)
    monkeypatch.setattr(_main, "_role_from_token", fake_role)

    r = await app_client.post(
        "/login",
        data={"email": "u@example.com", "password": "pw"},
    )

    assert r.status_code == 303
    assert r.headers["location"] == "/dashboard"


@pytest.mark.asyncio
async def test_login_caller_supplied_next_wins_for_admin(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the user clicks a deep link before logging in, ?next= still
    drives the post-login redirect — even for admins. Keeps deep-link
    flows intact.
    """
    from web_service import auth_client
    from web_service import main as _main

    async def fake_login(_url: str, _email: str, _password: str) -> auth_client.LoginResult:
        return auth_client.LoginResult(
            access_token="admin.jwt",
            refresh_token="r",
            expires_in=900,
            must_change_password=False,
        )

    def fake_role(_token: str) -> str | None:
        return "admin"

    monkeypatch.setattr(auth_client, "login", fake_login)
    monkeypatch.setattr(_main, "_role_from_token", fake_role)

    r = await app_client.post(
        "/login",
        data={"email": "admin@local", "password": "pw", "next": "/admin/settings"},
    )

    assert r.status_code == 303
    assert r.headers["location"] == "/admin/settings"
