"""CSRF protection tests (double-submit cookie pattern).

Covers:
- POST without csrf_token cookie or form field -> 403
- POST with valid csrf_token (cookie + form field match) -> proceeds
- POST with mismatched csrf_token -> 403
- GET requests are not affected / set the cookie
- Exempt paths work without CSRF
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio

# Mirror the constants from web_service.csrf so the test can collect
# even when the installed web_service package hasn't been updated yet
# (e.g. running in a worktree).
CSRF_COOKIE_NAME = "da_csrf"
CSRF_FORM_FIELD = "csrf_token"


@pytest.fixture(autouse=True)
def _auto_csrf_token() -> None:
    """Override the conftest permissive CSRF fixture.

    This test module needs the *real* CSRF middleware so it can verify
    that 403s fire on missing/mismatched tokens. We do nothing here,
    but the ``autouse=True`` at this module level shadows the conftest
    one. The ``app_client`` fixture below restores the real middleware
    explicitly.
    """


@pytest_asyncio.fixture
async def app_client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    from web_service import csrf as _csrf
    from web_service import deps as _deps
    from web_service import main as _main
    from web_service import settings as _settings

    _settings._settings = None
    _deps.reset_verifier()
    _main._reset_motd_cache()

    # Restore the real CSRF middleware (conftest patches it to be permissive).
    from web_service.csrf import csrf_middleware as _real_csrf_middleware

    monkeypatch.setattr(_csrf, "csrf_middleware", _real_csrf_middleware)

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    _main._reset_motd_cache()


# ---------------------------------------------------------------------------
# Helper: stub out auth_client / MOTD so pages render
# ---------------------------------------------------------------------------


def _stub_motd(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    async def fake_motd(_url: str) -> auth_client.MotdResult:
        return auth_client.MotdResult(active=False)

    monkeypatch.setattr(auth_client, "public_get_motd", fake_motd)


# ---------------------------------------------------------------------------
# GET requests: set the cookie, don't block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_sets_csrf_cookie(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /login should set the da_csrf cookie if absent."""
    _stub_motd(monkeypatch)

    r = await app_client.get("/login")
    assert r.status_code == 200
    assert CSRF_COOKIE_NAME in r.cookies
    # The token should also appear as a hidden input in the form.
    assert f'name="{CSRF_FORM_FIELD}"' in r.text


@pytest.mark.asyncio
async def test_get_preserves_existing_csrf_cookie(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /login with an existing cookie should not overwrite it."""
    _stub_motd(monkeypatch)

    existing_token = "my-existing-csrf-token"
    r = await app_client.get(
        "/login",
        cookies={CSRF_COOKIE_NAME: existing_token},
    )
    assert r.status_code == 200
    # Cookie should NOT be re-set (no Set-Cookie header for da_csrf).
    assert CSRF_COOKIE_NAME not in r.cookies
    # The existing token should be rendered in the form.
    assert existing_token in r.text


# ---------------------------------------------------------------------------
# POST without CSRF -> 403
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_without_csrf_cookie_returns_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login with no csrf cookie at all -> 403."""
    _stub_motd(monkeypatch)

    r = await app_client.post(
        "/login",
        data={"email": "test@example.com", "password": "secret"},
    )
    assert r.status_code == 403
    assert "CSRF" in r.text


@pytest.mark.asyncio
async def test_post_without_csrf_form_field_returns_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login with the cookie but no form field -> 403."""
    _stub_motd(monkeypatch)

    token = "valid-token-123"
    r = await app_client.post(
        "/login",
        data={"email": "test@example.com", "password": "secret"},
        cookies={CSRF_COOKIE_NAME: token},
    )
    assert r.status_code == 403
    assert "CSRF" in r.text


@pytest.mark.asyncio
async def test_post_with_mismatched_csrf_returns_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login with mismatched cookie vs form field -> 403."""
    _stub_motd(monkeypatch)

    r = await app_client.post(
        "/login",
        data={
            "email": "test@example.com",
            "password": "secret",
            CSRF_FORM_FIELD: "wrong-token",
        },
        cookies={CSRF_COOKIE_NAME: "correct-token"},
    )
    assert r.status_code == 403
    assert "CSRF" in r.text


# ---------------------------------------------------------------------------
# POST with valid CSRF -> proceeds normally
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_with_valid_csrf_proceeds(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login with matching cookie + form field -> processed by handler."""
    _stub_motd(monkeypatch)

    from web_service import auth_client

    async def fake_login(_url: str, _email: str, _password: str) -> auth_client.LoginResult:
        return auth_client.LoginResult(
            access_token="tok",
            refresh_token="ref",
            expires_in=3600,
            must_change_password=False,
        )

    monkeypatch.setattr(auth_client, "login", fake_login)

    token = "good-csrf-token-abc"
    r = await app_client.post(
        "/login",
        data={
            "email": "user@example.com",
            "password": "longenoughpw!!",
            "next": "",
            CSRF_FORM_FIELD: token,
        },
        cookies={CSRF_COOKIE_NAME: token},
        follow_redirects=False,
    )
    # Login succeeds -> 303 redirect (not 403).
    assert r.status_code == 303


@pytest.mark.asyncio
async def test_post_register_with_valid_csrf_proceeds(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /register with valid CSRF -> processed normally."""
    _stub_motd(monkeypatch)

    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        return True, None

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    token = "reg-csrf-token"
    r = await app_client.post(
        "/register",
        data={
            "email": "new@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
            CSRF_FORM_FIELD: token,
        },
        cookies={CSRF_COOKIE_NAME: token},
        follow_redirects=False,
    )
    assert r.status_code == 303


# ---------------------------------------------------------------------------
# Exempt paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_exempt_from_csrf(
    app_client: httpx.AsyncClient,
) -> None:
    """GET /healthz should work without any CSRF involvement."""
    # Health endpoint calls upstream services; it may return 200 or 503
    # depending on stubs but must never 403 (CSRF doesn't apply).
    r = await app_client.get("/healthz")
    assert r.status_code != 403
    # No csrf cookie should be set on health endpoint.
    assert CSRF_COOKIE_NAME not in r.cookies


@pytest.mark.asyncio
async def test_static_exempt_from_csrf(
    app_client: httpx.AsyncClient,
) -> None:
    """Static file paths should be exempt from CSRF."""
    # This might 404 (no actual file), but it shouldn't 403.
    r = await app_client.get("/static/nonexistent.css")
    assert r.status_code != 403


# ---------------------------------------------------------------------------
# Full flow: GET to obtain token, then POST with it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_csrf_flow_login(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate a real browser: GET form -> extract token -> POST with it."""
    _stub_motd(monkeypatch)

    from web_service import auth_client

    async def fake_login(_url: str, _email: str, _password: str) -> auth_client.LoginResult:
        return auth_client.LoginResult(
            access_token="tok",
            refresh_token="ref",
            expires_in=3600,
            must_change_password=False,
        )

    monkeypatch.setattr(auth_client, "login", fake_login)

    # Step 1: GET the login page to obtain the CSRF token.
    get_resp = await app_client.get("/login")
    assert get_resp.status_code == 200
    csrf_token = get_resp.cookies[CSRF_COOKIE_NAME]
    assert csrf_token

    # Verify it's in the HTML too.
    assert csrf_token in get_resp.text

    # Step 2: POST with the token.
    post_resp = await app_client.post(
        "/login",
        data={
            "email": "user@example.com",
            "password": "longenoughpw!!",
            "next": "",
            CSRF_FORM_FIELD: csrf_token,
        },
        cookies={CSRF_COOKIE_NAME: csrf_token},
        follow_redirects=False,
    )
    assert post_resp.status_code == 303


# ---------------------------------------------------------------------------
# CSRF on inline-error re-render (POST validation errors still have token)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csrf_token_available_on_post_validation_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a POST re-renders the form (e.g. invalid creds), csrf_token
    must still be present in the response so the user can re-submit."""
    _stub_motd(monkeypatch)

    from web_service import auth_client

    async def fake_login(_url: str, _email: str, _password: str) -> Any:
        raise auth_client.InvalidCredentials()

    monkeypatch.setattr(auth_client, "login", fake_login)

    token = "rerender-csrf-token"
    r = await app_client.post(
        "/login",
        data={
            "email": "bad@example.com",
            "password": "wrongpw",
            "next": "",
            CSRF_FORM_FIELD: token,
        },
        cookies={CSRF_COOKIE_NAME: token},
    )
    assert r.status_code == 401  # invalid credentials
    # The re-rendered form should still contain the csrf token.
    assert token in r.text
    assert f'name="{CSRF_FORM_FIELD}"' in r.text
