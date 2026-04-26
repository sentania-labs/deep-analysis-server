"""Web profile/self-service route tests.

Verifies the W3.5-B browser surface: GET /profile, GET/POST
/profile/edit, GET /profile/agents, POST /profile/agents/{id}/revoke.

Auth at the web layer is bypassed via FastAPI dependency overrides so
we can focus on handler behavior + auth_client wiring. End-to-end
auth flow is exercised by the smoke tests under ci/.
"""

from __future__ import annotations

import uuid
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


# ---------------------------------------------------------------------------
# GET /profile
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_profile_renders(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_get_me(_url: str, _token: str) -> auth_client.MeResult:
        return auth_client.MeResult(
            user_id=42, email="u@example.com", role="user", must_change_password=False
        )

    monkeypatch.setattr(auth_client, "get_me", fake_get_me)

    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "u@example.com" in r.text
    assert "/profile/edit" in r.text
    assert "/profile/agents" in r.text


@pytest.mark.asyncio
async def test_get_profile_unauthenticated_redirects(
    app_client: httpx.AsyncClient,
) -> None:
    r = await app_client.get("/profile")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


# ---------------------------------------------------------------------------
# GET /profile/edit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_profile_edit_prefills_email(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_get_me(_url: str, _token: str) -> auth_client.MeResult:
        return auth_client.MeResult(
            user_id=42, email="orig@example.com", role="user", must_change_password=False
        )

    monkeypatch.setattr(auth_client, "get_me", fake_get_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile/edit")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert 'name="email"' in r.text
    assert 'value="orig@example.com"' in r.text


# ---------------------------------------------------------------------------
# POST /profile/edit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_profile_edit_success_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_update_me(_url: str, _token: str, _email: str) -> tuple[bool, str | None]:
        return True, None

    monkeypatch.setattr(auth_client, "update_me", fake_update_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/profile/edit",
            data={"email": "renamed@example.com"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].endswith("/profile")


@pytest.mark.asyncio
async def test_post_profile_edit_email_taken_renders_inline(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_update_me(_url: str, _token: str, _email: str) -> tuple[bool, str | None]:
        return False, "email_taken"

    monkeypatch.setattr(auth_client, "update_me", fake_update_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/profile/edit",
            data={"email": "taken@example.com"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 409
    assert "already" in r.text.lower() or "taken" in r.text.lower()
    # Form re-rendered with the submitted email so the user can fix it.
    assert 'value="taken@example.com"' in r.text


@pytest.mark.asyncio
async def test_post_profile_edit_invalid_email_renders_inline(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_update_me(_url: str, _token: str, _email: str) -> tuple[bool, str | None]:
        return False, "invalid_email"

    monkeypatch.setattr(auth_client, "update_me", fake_update_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/edit", data={"email": "bad"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 400
    # The form is re-rendered, not redirected.
    assert 'name="email"' in r.text


@pytest.mark.asyncio
async def test_post_profile_edit_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "update_me", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/edit", data={"email": "x@example.com"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503
    assert "unavailable" in r.text.lower()


# ---------------------------------------------------------------------------
# GET /profile/agents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_profile_agents_lists_agents(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime

    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    aid = str(uuid.uuid4())

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> list[auth_client.AgentItem]:
        return [
            auth_client.AgentItem(
                agent_id=aid,
                machine_name="laptop-1",
                client_version="0.4.0",
                created_at=datetime(2026, 4, 1, tzinfo=UTC),
                last_seen_at=datetime(2026, 4, 25, tzinfo=UTC),
                revoked_at=None,
            ),
            auth_client.AgentItem(
                agent_id=str(uuid.uuid4()),
                machine_name="dead-laptop",
                client_version=None,
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
                last_seen_at=None,
                revoked_at=datetime(2026, 4, 20, tzinfo=UTC),
            ),
        ]

    monkeypatch.setattr(auth_client, "list_my_agents", fake_list)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "laptop-1" in r.text
    assert "0.4.0" in r.text
    assert "dead-laptop" in r.text
    # Revoke button only appears for active (non-revoked) agents.
    assert f"/profile/agents/{aid}/revoke" in r.text


# ---------------------------------------------------------------------------
# POST /profile/agents/{id}/revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_revoke_my_agent_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_revoke(_url: str, _token: str, agent_id: str) -> tuple[bool, str | None]:
        captured["agent_id"] = agent_id
        return True, None

    monkeypatch.setattr(auth_client, "revoke_my_agent", fake_revoke)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    aid = str(uuid.uuid4())
    try:
        r = await app_client.post(f"/profile/agents/{aid}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].endswith("/profile/agents")
    assert captured["agent_id"] == aid


@pytest.mark.asyncio
async def test_post_revoke_my_agent_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "revoke_my_agent", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(f"/profile/agents/{uuid.uuid4()}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


# ---------------------------------------------------------------------------
# AuthForbidden handling — auth's authoritative session check rejected the
# call even though the JWT locally validated. Self-service routes redirect
# to /login (session-expired flow) rather than render a 503.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_profile_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "get_me", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_get_profile_edit_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "get_me", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile/edit")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_post_profile_edit_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "update_me", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/edit", data={"email": "x@example.com"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_get_profile_agents_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "list_my_agents", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_post_revoke_my_agent_redirects_to_login_on_auth_forbidden(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated session revocation")

    monkeypatch.setattr(auth_client, "revoke_my_agent", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(f"/profile/agents/{uuid.uuid4()}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/login"
