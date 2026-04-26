"""Web admin route tests.

Verifies the W3.5-C browser surface: GET /admin/users (list),
GET /admin/users/{id} (detail), POST /admin/users/{id}/delete,
POST /admin/users/{id}/reset-password.

Like the profile route tests, web-layer auth is bypassed via
FastAPI dependency overrides so we can focus on handler behavior +
auth_client wiring.
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


def _sample_users() -> list[Any]:
    from web_service import auth_client

    return [
        auth_client.UserItem(
            id=1,
            email="admin@local",
            role="admin",
            disabled=False,
            must_change_password=False,
            created_at=datetime(2026, 4, 26, 12, 0, tzinfo=UTC),
            updated_at=datetime(2026, 4, 26, 12, 0, tzinfo=UTC),
        ),
        auth_client.UserItem(
            id=2,
            email="testuser@local",
            role="user",
            disabled=False,
            must_change_password=True,
            created_at=datetime(2026, 4, 26, 12, 1, tzinfo=UTC),
            updated_at=datetime(2026, 4, 26, 12, 1, tzinfo=UTC),
        ),
    ]


# ---------------------------------------------------------------------------
# GET /admin/users
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_admin_users_lists_users_for_admin(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        return _sample_users(), 2

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "admin@local" in r.text
    assert "testuser@local" in r.text
    # Both delete and reset-password actions surfaced for testuser.
    assert "/admin/users/2/delete" in r.text
    assert "/admin/users/2/reset-password" in r.text


@pytest.mark.asyncio
async def test_get_admin_users_hides_self_delete_button(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The admin viewing the list shouldn't see a delete button for themselves."""
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        return _sample_users(), 2

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # admin (id=1) should NOT have a delete form rendered for self.
    assert "/admin/users/1/delete" not in r.text
    # Other users should still have one.
    assert "/admin/users/2/delete" in r.text


@pytest.mark.asyncio
async def test_get_admin_users_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_admin_users_unauth_redirects(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/admin/users")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_get_admin_users_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_list_users", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


# ---------------------------------------------------------------------------
# POST /admin/users/{id}/delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_delete_user_redirects_on_success(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_delete(_url: str, _token: str, user_id: int) -> tuple[bool, str | None]:
        captured["user_id"] = user_id
        return True, None

    monkeypatch.setattr(auth_client, "admin_delete_user", fake_delete)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].endswith("/admin/users")
    assert captured["user_id"] == 2


@pytest.mark.asyncio
async def test_post_delete_user_self_blocks_at_web_layer(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-delete must short-circuit before hitting auth.

    Auth enforces the same guard but the web layer should not even
    issue the call when the URL clearly targets the caller.
    """
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    called = {"hit": False}

    async def fake_delete(_url: str, _token: str, _user_id: int) -> tuple[bool, str | None]:
        called["hit"] = True
        return True, None

    monkeypatch.setattr(auth_client, "admin_delete_user", fake_delete)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/1/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 400
    assert called["hit"] is False
    assert "yourself" in r.text.lower() or "self" in r.text.lower()


@pytest.mark.asyncio
async def test_post_delete_user_propagates_auth_error_inline(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        return _sample_users(), 2

    async def fake_delete(_url: str, _token: str, _user_id: int) -> tuple[bool, str | None]:
        return False, "cannot_delete_last_admin"

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    monkeypatch.setattr(auth_client, "admin_delete_user", fake_delete)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 400
    assert "last admin" in r.text.lower()


@pytest.mark.asyncio
async def test_post_delete_user_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_delete_user", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_post_delete_user_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# POST /admin/users/{id}/reset-password
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_reset_password_renders_temp(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_reset(_url: str, _token: str, user_id: int) -> tuple[str | None, str | None]:
        assert user_id == 2
        return "TempStrongPwGoesHere1234", None

    monkeypatch.setattr(auth_client, "admin_reset_password", fake_reset)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/reset-password")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # The temp password is rendered exactly once for the admin to copy.
    assert "TempStrongPwGoesHere1234" in r.text
    # It is also presented in a code/strong block (we expect the
    # template to wrap it visibly — assert one of the common markers).
    assert "<code>" in r.text or "monospace" in r.text.lower() or 'class="temp-password"' in r.text


@pytest.mark.asyncio
async def test_post_reset_password_user_not_found_propagates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        return _sample_users(), 2

    async def fake_reset(*_a: Any, **_kw: Any) -> tuple[str | None, str | None]:
        return None, "user_not_found"

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    monkeypatch.setattr(auth_client, "admin_reset_password", fake_reset)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/999/reset-password")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404


@pytest.mark.asyncio
async def test_post_reset_password_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_reset_password", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/reset-password")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_post_reset_password_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/reset-password")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# AuthForbidden handling — auth's authoritative role/session check rejected
# the call even though the JWT claim said `admin` (revoked session, demoted
# role). Should render the admin-denied page, not a 503.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_admin_users_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_list_users", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403
    assert "503" not in r.text


@pytest.mark.asyncio
async def test_post_delete_user_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_delete_user", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_reset_password_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_reset_password", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/2/reset-password")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Pagination (?page=&per_page=)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_admin_users_passes_pagination_to_auth_client(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        captured["limit"] = limit
        captured["offset"] = offset
        return [], 0

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users?page=3&per_page=25")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert captured == {"limit": 25, "offset": 50}


@pytest.mark.asyncio
async def test_get_admin_users_renders_next_link_when_more_pages(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        return _sample_users(), 250

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users?page=1&per_page=2")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "page=2" in r.text
    assert "Next" in r.text
    # Page 1 has no previous link.
    assert "page=0" not in r.text


@pytest.mark.asyncio
async def test_get_admin_users_renders_prev_link_on_later_page(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        # Last page: 3 of 3 items, fits on a single per_page=2 page-2.
        return [_sample_users()[1]], 3

    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users?page=2&per_page=2")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # Prev link to page=1 with the same per_page.
    assert "page=1" in r.text
    assert "Previous" in r.text
    # No next on the last page.
    assert "Next" not in r.text


@pytest.mark.asyncio
async def test_get_admin_users_rejects_per_page_above_ceiling(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/users?per_page=500")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 422
