"""Web admin invites route tests (W3.6.4).

Covers /admin/invites GET (list), POST (create + render plaintext once),
and POST /admin/invites/{id}/revoke. Auth is bypassed via dependency
overrides; the auth service surface is faked through monkeypatched
auth_client wrappers.
"""

from __future__ import annotations

import uuid
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


def _sample_invite_item() -> Any:
    from web_service import auth_client

    return auth_client.InviteItem(
        id=str(uuid.uuid4()),
        created_by_user_id=1,
        created_by_email="admin@local",
        created_at=datetime.now(UTC) - timedelta(hours=2),
        expires_at=datetime.now(UTC) + timedelta(hours=166),
    )


# ---------------------------------------------------------------------------
# GET /admin/invites
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_invites_renders_list(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    sample = _sample_invite_item()

    async def fake_list(
        _url: str, _token: str, page: int = 1, per_page: int = 50
    ) -> tuple[list[Any], int]:
        return [sample], 1

    monkeypatch.setattr(auth_client, "admin_list_invites", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/invites")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Pending invites" in r.text
    assert "admin@local" in r.text
    assert sample.id in r.text


@pytest.mark.asyncio
async def test_get_invites_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/invites")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_invites_unauth_redirects(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/admin/invites")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


# ---------------------------------------------------------------------------
# POST /admin/invites — create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_create_invite_renders_plaintext_and_invite_url(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    plaintext = "test-plaintext-tok-abc"
    invite_id = str(uuid.uuid4())

    async def fake_create(_url: str, _token: str, _hours: int) -> auth_client.CreatedInvite:
        return auth_client.CreatedInvite(
            id=invite_id,
            token=plaintext,
            expires_at=datetime.now(UTC) + timedelta(hours=168),
            created_at=datetime.now(UTC),
        )

    async def fake_list(
        _url: str, _token: str, page: int = 1, per_page: int = 50
    ) -> tuple[list[Any], int]:
        return [], 0

    monkeypatch.setattr(auth_client, "admin_create_invite", fake_create)
    monkeypatch.setattr(auth_client, "admin_list_invites", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/invites", data={"expires_in_hours": "168"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert plaintext in r.text
    # Invite URL should embed the plaintext token.
    assert f"/register?token={plaintext}" in r.text
    assert "shown" in r.text  # one-time-shown notice


@pytest.mark.asyncio
async def test_post_create_invite_503_on_auth_outage(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_create_invite", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/invites", data={"expires_in_hours": "168"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_post_create_invite_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/invites", data={"expires_in_hours": "168"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# POST /admin/invites/{id}/revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_revoke_invite_redirects_on_success(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_revoke(_url: str, _token: str, _id: str) -> tuple[bool, str | None]:
        return True, None

    monkeypatch.setattr(auth_client, "admin_revoke_invite", fake_revoke)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(f"/admin/invites/{uuid.uuid4()}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/invites")


@pytest.mark.asyncio
async def test_post_revoke_invite_404_renders_inline_error(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_revoke(_url: str, _token: str, _id: str) -> tuple[bool, str | None]:
        return False, "invite_not_found"

    async def fake_list(
        _url: str, _token: str, page: int = 1, per_page: int = 50
    ) -> tuple[list[Any], int]:
        return [], 0

    monkeypatch.setattr(auth_client, "admin_revoke_invite", fake_revoke)
    monkeypatch.setattr(auth_client, "admin_list_invites", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(f"/admin/invites/{uuid.uuid4()}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert "no longer exists" in r.text
