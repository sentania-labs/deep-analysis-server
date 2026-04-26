"""Web auth_client self-service helpers.

Mocks httpx so we can assert request shape + response translation
without needing a live auth service. The integration tests under
``tests/integration/`` cover end-to-end with a real stack.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest


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


def _stub_patch(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    capture: dict[str, Any] | None = None,
) -> None:
    async def _patch(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        if capture is not None:
            capture["url"] = url
            capture["kwargs"] = kwargs
        return response

    monkeypatch.setattr(httpx.AsyncClient, "patch", _patch)


# ---------------------------------------------------------------------------
# get_me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_me_returns_me_result(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_get(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "user_id": 7,
                "email": "u@example.com",
                "role": "user",
                "must_change_password": False,
            },
        ),
        capture,
    )

    result = await auth_client.get_me("http://auth:8000", "tok")
    assert result.user_id == 7
    assert result.email == "u@example.com"
    assert result.role == "user"
    assert result.must_change_password is False
    assert capture["url"] == "http://auth:8000/auth/me"
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_get_me_raises_on_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "get", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.get_me("http://auth:8000", "tok")


@pytest.mark.asyncio
async def test_get_me_raises_on_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_get(monkeypatch, httpx.Response(500, text="boom"))

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.get_me("http://auth:8000", "tok")


# ---------------------------------------------------------------------------
# list_my_agents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_my_agents_returns_items(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    agent_id = str(uuid.uuid4())
    capture: dict[str, Any] = {}
    _stub_get(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "agents": [
                    {
                        "agent_id": agent_id,
                        "user_id": 7,
                        "user_email": "u@example.com",
                        "machine_name": "laptop-1",
                        "client_version": "0.4.0",
                        "created_at": "2026-04-26T12:00:00+00:00",
                        "last_seen_at": "2026-04-26T12:05:00+00:00",
                        "revoked_at": None,
                    }
                ],
                "total": 1,
            },
        ),
        capture,
    )

    items = await auth_client.list_my_agents("http://auth:8000", "tok", limit=10, offset=0)
    assert len(items) == 1
    assert items[0].agent_id == agent_id
    assert items[0].machine_name == "laptop-1"
    assert items[0].client_version == "0.4.0"
    assert items[0].revoked_at is None
    assert items[0].last_seen_at is not None
    # Pagination is forwarded as query params.
    assert capture["kwargs"]["params"] == {"limit": 10, "offset": 0}


@pytest.mark.asyncio
async def test_list_my_agents_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_get(monkeypatch, httpx.Response(200, json={"agents": [], "total": 0}))

    items = await auth_client.list_my_agents("http://auth:8000", "tok")
    assert items == []


@pytest.mark.asyncio
async def test_list_my_agents_translates_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ReadTimeout("auth slow")

    monkeypatch.setattr(httpx.AsyncClient, "get", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.list_my_agents("http://auth:8000", "tok")


# ---------------------------------------------------------------------------
# update_me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_me_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    capture: dict[str, Any] = {}
    _stub_patch(
        monkeypatch,
        httpx.Response(
            200,
            json={
                "user_id": 7,
                "email": "renamed@example.com",
                "role": "user",
                "must_change_password": False,
            },
        ),
        capture,
    )

    ok, err = await auth_client.update_me("http://auth:8000", "tok", "renamed@example.com")
    assert ok is True
    assert err is None
    assert capture["kwargs"]["json"] == {"email": "renamed@example.com"}
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_update_me_email_taken_returns_email_taken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_patch(
        monkeypatch,
        httpx.Response(409, json={"detail": {"error": "email_already_exists"}}),
    )

    ok, err = await auth_client.update_me("http://auth:8000", "tok", "taken@example.com")
    assert ok is False
    assert err == "email_taken"


@pytest.mark.asyncio
async def test_update_me_validation_returns_invalid_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    _stub_patch(
        monkeypatch,
        httpx.Response(422, json={"detail": [{"msg": "too short"}]}),
    )

    ok, err = await auth_client.update_me("http://auth:8000", "tok", "")
    assert ok is False
    assert err == "invalid_email"


@pytest.mark.asyncio
async def test_update_me_translates_transport_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "patch", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.update_me("http://auth:8000", "tok", "x@example.com")


# ---------------------------------------------------------------------------
# revoke_my_agent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_my_agent_success(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    aid = str(uuid.uuid4())
    capture: dict[str, Any] = {}
    _stub_post(monkeypatch, httpx.Response(204), capture)

    ok, err = await auth_client.revoke_my_agent("http://auth:8000", "tok", aid)
    assert ok is True
    assert err is None
    assert capture["url"] == f"http://auth:8000/auth/me/agents/{aid}/revoke"
    assert capture["kwargs"]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_revoke_my_agent_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_post(
        monkeypatch,
        httpx.Response(403, json={"detail": {"error": "forbidden"}}),
    )

    ok, err = await auth_client.revoke_my_agent("http://auth:8000", "tok", str(uuid.uuid4()))
    assert ok is False
    assert err == "forbidden"


@pytest.mark.asyncio
async def test_revoke_my_agent_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    from web_service import auth_client

    _stub_post(
        monkeypatch,
        httpx.Response(404, json={"detail": {"error": "agent_not_found"}}),
    )

    ok, err = await auth_client.revoke_my_agent("http://auth:8000", "tok", str(uuid.uuid4()))
    assert ok is False
    assert err == "not_found"


@pytest.mark.asyncio
async def test_revoke_my_agent_translates_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise httpx.ConnectError("auth unreachable")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)

    with pytest.raises(auth_client.AuthClientError):
        await auth_client.revoke_my_agent("http://auth:8000", "tok", str(uuid.uuid4()))
