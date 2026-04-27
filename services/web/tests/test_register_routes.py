"""Public /register route tests (W3.6.4)."""

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


# ---------------------------------------------------------------------------
# GET /register — invite_only mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_register_invite_only_no_token_blocks_form(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "invite_only"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)

    r = await app_client.get("/register")
    assert r.status_code == 200
    assert "invite-only" in r.text.lower()
    # Form is suppressed in this case — no email input rendered.
    assert 'name="email"' not in r.text


@pytest.mark.asyncio
async def test_get_register_invite_only_with_token_renders_form(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "invite_only"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)

    r = await app_client.get("/register?token=some-token")
    assert r.status_code == 200
    assert 'name="email"' in r.text
    assert 'name="password"' in r.text
    # Token is preserved as a hidden field for POST.
    assert 'value="some-token"' in r.text


@pytest.mark.asyncio
async def test_get_register_open_mode_renders_form_without_token(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)

    r = await app_client.get("/register")
    assert r.status_code == 200
    assert 'name="email"' in r.text
    assert "optional" in r.text.lower()


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_register_success_redirects_to_login(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        return True, None

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    r = await app_client.post(
        "/register",
        data={
            "email": "new@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
        },
    )
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_post_register_password_mismatch_inline_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)

    r = await app_client.post(
        "/register",
        data={
            "email": "new@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "differentpw!!",
        },
    )
    assert r.status_code == 400
    assert "Passwords do not match" in r.text


@pytest.mark.asyncio
async def test_post_register_invite_required_renders_invite_only_page(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "invite_only"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        return False, "invite_required"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    r = await app_client.post(
        "/register",
        data={
            "email": "new@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
        },
    )
    assert r.status_code == 403
    assert "invite-only" in r.text.lower()


@pytest.mark.asyncio
async def test_post_register_invalid_invite_token_inline_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "invite_only"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        return False, "invalid_invite_token"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    r = await app_client.post(
        "/register",
        data={
            "email": "new@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
            "token": "bad-token",
        },
    )
    assert r.status_code == 403
    assert "invalid" in r.text.lower()


@pytest.mark.asyncio
async def test_post_register_email_taken(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        return False, "email_already_exists"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    r = await app_client.post(
        "/register",
        data={
            "email": "taken@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
        },
    )
    assert r.status_code == 409
    assert "already exists" in r.text


@pytest.mark.asyncio
async def test_post_register_weak_password_inline_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        return False, "weak_password"

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    r = await app_client.post(
        "/register",
        data={
            "email": "u@example.com",
            "password": "shortpw",
            "confirm_password": "shortpw",
        },
    )
    assert r.status_code == 400
    assert "complexity" in r.text.lower() or "12 character" in r.text.lower()


@pytest.mark.asyncio
async def test_post_register_email_already_taken_renders_inline_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth's race-recovery 409 ``email_already_taken`` is raised by
    auth_client as a typed exception. The /register POST handler must
    catch it and re-render the form with a friendly inline message —
    not 500, not the generic "Could not register account." fallback."""
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    async def fake_register(
        _url: str, _email: str, _password: str, _token: str | None
    ) -> tuple[bool, str | None]:
        raise auth_client.EmailAlreadyTaken()

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", fake_register)

    r = await app_client.post(
        "/register",
        data={
            "email": "racing@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
        },
    )
    assert r.status_code == 409
    assert "An account with this email already exists" in r.text
    assert "Try logging in or use a different address" in r.text
    # Form is re-rendered (not a redirect / 500), so the email field
    # is preserved for the user.
    assert 'name="email"' in r.text
    assert "racing@example.com" in r.text


@pytest.mark.asyncio
async def test_post_register_503_on_auth_outage(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return "open"

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)
    monkeypatch.setattr(auth_client, "public_register", boom)

    r = await app_client.post(
        "/register",
        data={
            "email": "u@example.com",
            "password": "longenoughpw!!",
            "confirm_password": "longenoughpw!!",
        },
    )
    assert r.status_code == 503
