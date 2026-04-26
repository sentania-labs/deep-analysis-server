"""Web auth_client admin helpers.

Mocks httpx so we can assert request shape + response translation
for the admin-only auth endpoints. End-to-end coverage lives in
``ci/smoke_ui.sh``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest


def _stub_get(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    capture: dict[str, Any] | None = None,
) -> None:
    async def _get(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        if capture is not None:
            capture["url"] = url
            capture["kwargs"] = kwargs
        return response

    monkeypatch.setattr(httpx.AsyncClient, "get", _get)


def _stub_post(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    capture: dict[str, Any] | None = None,
) -> None:
    async def _post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        if capture is not None:
            capture["url"] = url
            capture["kwargs"] = kwargs
        return response

    monkeypatch.setattr(httpx.AsyncClient, "post", _post)


def _stub_delete(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    capture: dict[str, Any] | None = None,
) -> None:
    async def _delete(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        if capture is not None:
            capture["url"] = url
            capture["kwargs"] = kwargs
        return response

    monkeypatch.setattr(httpx.AsyncClient, "delete", _delete)


# ---------------------------------------------------------------------------
# admin_list_users
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_list_users_returns_items(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_get(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "users": [
                    {
                        "id": 1,
                        "email": "admin@local",
                        "role": "admin",
                        "disabled": False,
                        "must_change_password": False,
                        "created_at": "2026-04-26T12:00:00+00:00",
                        "updated_at": "2026-04-26T12:00:00+00:00",
                    },
                    {
                        "id": 2,
                        "email": "testuser@local",
                        "role": "user",
                        "disabled": False,
                        "must_change_password": True,
                        "created_at": "2026-04-26T12:01:00+00:00",
                        "updated_at": "2026-04-26T12:01:00+00:00",
                    },
                ],
                "total": 2,
            },
        ),
        capture,
    )

    items, total = await auth_client.admin_list_users(
        "http://auth:8000", "admin-tok", limit=10, offset=0
    )
    assert total == 2
    assert len(items) == 2
    assert items[0].id == 1
    assert items[0].email == "admin@local"
    assert items[0].role == "admin"
    assert items[1].email == "testuser@local"
    assert items[1].must_change_password is True
    assert capture["url"] == "http://auth:8000/admin/users"
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer admin-tok"
    assert capture["kwargs"]["params"] == {"limit": 10, "offset": 0}


@pytest.mark.asyncio
async def test_admin_list_users_translates_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "get", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_list_users("http://auth:8000", "tok")


@pytest.mark.asyncio
async def test_admin_list_users_raises_on_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_get(monkeypatch, httpx.Response(500, text="boom"))

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_list_users("http://auth:8000", "tok")


@pytest.mark.asyncio
async def test_admin_list_users_raises_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-admin token reaching this helper is a programmer error.

    The web layer is supposed to reject non-admins before the call;
    surfacing 403 as AuthClientError keeps the helper honest.
    """
    from web_service import auth_client

    _stub_get(monkeypatch, httpx.Response(403, json={"detail": {"error": "admin_required"}}))

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_list_users("http://auth:8000", "tok")


# ---------------------------------------------------------------------------
# admin_delete_user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_delete_user_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_delete(monkeypatch, httpx.Response(204), capture)

    ok, err = await auth_client.admin_delete_user("http://auth:8000", "tok", 7)
    assert ok is True
    assert err is None
    assert capture["url"] == "http://auth:8000/admin/users/7"
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_admin_delete_user_self_returns_cannot_delete_self(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_delete(
        monkeypatch,
        httpx.Response(400, json={"detail": {"error": "cannot_delete_self"}}),
    )
    ok, err = await auth_client.admin_delete_user("http://auth:8000", "tok", 1)
    assert ok is False
    assert err == "cannot_delete_self"


@pytest.mark.asyncio
async def test_admin_delete_user_last_admin_returns_cannot_delete_last_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_delete(
        monkeypatch,
        httpx.Response(400, json={"detail": {"error": "cannot_delete_last_admin"}}),
    )
    ok, err = await auth_client.admin_delete_user("http://auth:8000", "tok", 5)
    assert ok is False
    assert err == "cannot_delete_last_admin"


@pytest.mark.asyncio
async def test_admin_delete_user_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_delete(
        monkeypatch,
        httpx.Response(404, json={"detail": {"error": "user_not_found"}}),
    )
    ok, err = await auth_client.admin_delete_user("http://auth:8000", "tok", 999)
    assert ok is False
    assert err == "user_not_found"


@pytest.mark.asyncio
async def test_admin_delete_user_translates_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "delete", boom)
    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_delete_user("http://auth:8000", "tok", 7)


# ---------------------------------------------------------------------------
# admin_reset_password
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_reset_password_returns_temp(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_post(
        monkeypatch,
        httpx.Response(200, json={"temporary_password": "abc123abc123abc123ab"}),
        capture,
    )
    temp, err = await auth_client.admin_reset_password("http://auth:8000", "tok", 7)
    assert temp == "abc123abc123abc123ab"
    assert err is None
    assert capture["url"] == "http://auth:8000/admin/users/7/reset-password"
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_admin_reset_password_user_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_post(
        monkeypatch,
        httpx.Response(404, json={"detail": {"error": "user_not_found"}}),
    )
    temp, err = await auth_client.admin_reset_password("http://auth:8000", "tok", 999)
    assert temp is None
    assert err == "user_not_found"


@pytest.mark.asyncio
async def test_admin_reset_password_translates_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ReadTimeout("auth slow")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_reset_password("http://auth:8000", "tok", 7)
