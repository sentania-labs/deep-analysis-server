"""Web auth_client settings helpers (W3.6.3).

Mocks httpx so we can assert request shape + response translation for
the registration-mode GET/PUT wrappers. End-to-end coverage lives in
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


def _stub_put(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    capture: dict[str, Any] | None = None,
) -> None:
    async def _put(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        if capture is not None:
            capture["url"] = url
            capture["kwargs"] = kwargs
        return response

    monkeypatch.setattr(httpx.AsyncClient, "put", _put)


# ---------------------------------------------------------------------------
# admin_get_registration_mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_returns_view(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_get(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "mode": "invite_only",
                "updated_at": "2026-04-26T12:00:00+00:00",
                "updated_by_user_id": 1,
            },
        ),
        capture,
    )
    view = await auth_client.admin_get_registration_mode("http://auth:8000", "tok")
    assert view.mode == "invite_only"
    assert view.updated_by_user_id == 1
    assert view.updated_at is not None
    assert capture["url"] == "http://auth:8000/admin/settings/registration-mode"
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_get_handles_null_updater(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_get(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "mode": "open",
                "updated_at": "2026-04-26T12:00:00+00:00",
                "updated_by_user_id": None,
            },
        ),
    )
    view = await auth_client.admin_get_registration_mode("http://auth:8000", "tok")
    assert view.updated_by_user_id is None


@pytest.mark.asyncio
async def test_get_translates_403_to_auth_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_get(monkeypatch, httpx.Response(403))
    with pytest.raises(auth_client.AuthForbidden):
        await auth_client.admin_get_registration_mode("http://auth:8000", "tok")


@pytest.mark.asyncio
async def test_get_translates_5xx_to_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_get(monkeypatch, httpx.Response(503, text="upstream down"))
    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_get_registration_mode("http://auth:8000", "tok")


@pytest.mark.asyncio
async def test_get_translates_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "get", boom)
    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_get_registration_mode("http://auth:8000", "tok")


# ---------------------------------------------------------------------------
# admin_set_registration_mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_success_returns_view(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_put(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "mode": "open",
                "updated_at": "2026-04-26T12:00:00+00:00",
                "updated_by_user_id": 1,
            },
        ),
        capture,
    )
    view, err = await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "open")
    assert err is None
    assert view is not None
    assert view.mode == "open"
    assert capture["url"] == "http://auth:8000/admin/settings/registration-mode"
    assert capture["kwargs"]["json"] == {"mode": "open"}
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_set_403_not_root_admin_returns_inline_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth's UID=1 gate must not bubble up as AuthForbidden.

    Surfacing it as an inline error code lets the web layer keep the
    settings page rendered (read-only) for the demoted admin instead
    of bouncing them to /login.
    """
    from web_service import auth_client

    _stub_put(
        monkeypatch,
        httpx.Response(403, json={"detail": {"error": "not_root_admin"}}),
    )
    view, err = await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "open")
    assert view is None
    assert err == "not_root_admin"


@pytest.mark.asyncio
async def test_set_403_other_raises_auth_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_put(
        monkeypatch,
        httpx.Response(403, json={"detail": {"error": "forbidden"}}),
    )
    with pytest.raises(auth_client.AuthForbidden):
        await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "open")


@pytest.mark.asyncio
async def test_set_401_raises_auth_forbidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_put(monkeypatch, httpx.Response(401))
    with pytest.raises(auth_client.AuthForbidden):
        await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "open")


@pytest.mark.asyncio
async def test_set_422_returns_invalid_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_put(monkeypatch, httpx.Response(422, json={"detail": []}))
    view, err = await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "garbage")
    assert view is None
    assert err == "invalid_mode"


@pytest.mark.asyncio
async def test_set_5xx_raises_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_put(monkeypatch, httpx.Response(500, text="boom"))
    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "open")


@pytest.mark.asyncio
async def test_set_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "put", boom)
    with pytest.raises(auth_client.AuthClientError):
        await auth_client.admin_set_registration_mode("http://auth:8000", "tok", "open")
