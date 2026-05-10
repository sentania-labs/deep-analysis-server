"""POST /profile/agents/registration-code route tests.

Covers the W3.5-B+ agent registration UX: clicking "Generate
Registration Code" on /profile/agents posts here, the handler asks
auth to mint a code, then re-renders the agents page with the code
displayed for the user to enter into their agent.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
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


def _override_user(token: str = "fake-tok") -> Any:
    from web_service import deps as _deps

    fake_user = _deps.BrowserUser(
        user_id=42,
        email="u@example.com",
        role="user",
        must_change_password=False,
        scope=None,
        token=token,
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_user

    return _dep, fake_user


@pytest.mark.asyncio
async def test_post_registration_code_renders_code(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    expires = datetime.now(UTC) + timedelta(minutes=10)

    async def fake_mint(_url: str, _token: str) -> auth_client.RegistrationCodeResult:
        return auth_client.RegistrationCodeResult(code="ABCD-EFGH", expires_at=expires)

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AgentItem], int]:
        return [], 0

    monkeypatch.setattr(auth_client, "mint_registration_code", fake_mint)
    monkeypatch.setattr(auth_client, "list_my_agents", fake_list)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/agents/registration-code")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "ABCD-EFGH" in r.text
    assert "Register New Agent" in r.text


@pytest.mark.asyncio
async def test_post_registration_code_tolerates_list_outage(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The list refetch is best-effort. If it fails, the code still
    renders so the user can complete the registration."""
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    expires = datetime.now(UTC) + timedelta(minutes=10)

    async def fake_mint(_url: str, _token: str) -> auth_client.RegistrationCodeResult:
        return auth_client.RegistrationCodeResult(code="WXYZ-1234", expires_at=expires)

    async def boom_list(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("list failed")

    monkeypatch.setattr(auth_client, "mint_registration_code", fake_mint)
    monkeypatch.setattr(auth_client, "list_my_agents", boom_list)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/agents/registration-code")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "WXYZ-1234" in r.text


@pytest.mark.asyncio
async def test_post_registration_code_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "mint_registration_code", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/agents/registration-code")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_post_registration_code_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "mint_registration_code", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/agents/registration-code")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503
    assert "unavailable" in r.text.lower()


@pytest.mark.asyncio
async def test_post_registration_code_admin_bounces_to_panel(
    app_client: httpx.AsyncClient,
) -> None:
    """Admins have no self-service surface; should redirect to /admin/users."""
    from web_service import deps as _deps
    from web_service import main as _main

    admin_user = _deps.BrowserUser(
        user_id=1,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-tok",
    )

    async def dep() -> _deps.BrowserUser:
        return admin_user

    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/agents/registration-code")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"


@pytest.mark.asyncio
async def test_get_profile_agents_shows_register_section(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Register New Agent section renders even when no code has
    been minted yet — the form is the entry point for minting."""
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AgentItem], int]:
        return [], 0

    monkeypatch.setattr(auth_client, "list_my_agents", fake_list)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Register New Agent" in r.text
    assert "/profile/agents/registration-code" in r.text
    assert "Generate Registration Code" in r.text
