"""Auth-boundary transport-error translation in the web service.

These tests verify two behaviors:

1. ``auth_client.login`` and ``auth_client.change_password`` translate
   raw ``httpx`` transport errors into ``AuthClientError`` so callers
   get a uniform exception type at the boundary.
2. The ``POST /login`` and ``POST /settings/password`` handlers catch
   ``AuthClientError`` and render a 503 page in the appropriate
   template instead of bubbling a 500.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio


@pytest.mark.asyncio
async def test_login_translates_transport_error_to_auth_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.login("http://auth:8000", "u@example.com", "pw")


@pytest.mark.asyncio
async def test_change_password_translates_transport_error_to_auth_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.change_password("http://auth:8000", "tok", "old-pw", "new-pw-9876")


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


@pytest.mark.asyncio
async def test_post_login_returns_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def raise_unreachable(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "login", raise_unreachable)

    r = await app_client.post(
        "/login",
        data={"email": "u@example.com", "password": "pw", "next": ""},
    )
    assert r.status_code == 503
    assert "Authentication service unavailable" in r.text
    # Login template marker — confirms the failure rendered the right page.
    assert 'name="password"' in r.text
    assert 'action="/login"' in r.text


@pytest.mark.asyncio
async def test_post_password_change_returns_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def raise_unreachable(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "change_password", raise_unreachable)

    fake_user = _deps.BrowserUser(
        user_id=1,
        email="u@example.com",
        role="user",
        must_change_password=True,
        scope=_deps.PASSWORD_CHANGE_SCOPE,
        token="fake-token",
    )

    async def fake_user_dep() -> _deps.BrowserUser:
        return fake_user

    _main.app.dependency_overrides[_deps.get_current_browser_user_any_scope] = fake_user_dep
    try:
        r = await app_client.post(
            "/settings/password",
            data={
                "current_password": "old-pw",
                "new_password": "new-pw-9876",
                "confirm_password": "new-pw-9876",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503
    assert "Authentication service unavailable" in r.text
    # Password template marker — confirms the failure rendered the right page.
    assert 'name="new_password"' in r.text
    assert 'action="/settings/password"' in r.text


@pytest.mark.asyncio
async def test_post_password_change_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AuthForbidden from change_password (revoked session, current password
    rejected) bounces the caller to /login rather than rendering a 503 — the
    cookie's no longer valid at auth, so re-auth is the only path forward."""
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def raise_forbidden(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "change_password", raise_forbidden)

    fake_user = _deps.BrowserUser(
        user_id=1,
        email="u@example.com",
        role="user",
        must_change_password=True,
        scope=_deps.PASSWORD_CHANGE_SCOPE,
        token="fake-token",
    )

    async def fake_user_dep() -> _deps.BrowserUser:
        return fake_user

    _main.app.dependency_overrides[_deps.get_current_browser_user_any_scope] = fake_user_dep
    try:
        r = await app_client.post(
            "/settings/password",
            data={
                "current_password": "old-pw",
                "new_password": "new-pw-9876",
                "confirm_password": "new-pw-9876",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"
