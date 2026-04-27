"""Web admin agents route tests (W3.6.2).

Covers the cross-user agents view at GET /admin/agents and the
revoke action at POST /admin/agents/{id}/revoke. Web-layer auth
is bypassed via dependency overrides so the focus is handler
behaviour + auth_client wiring.
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


def _sample_agents(*, count: int = 2, total: int | None = None) -> tuple[list[Any], int]:
    from web_service import auth_client

    base = [
        auth_client.AdminAgentItem(
            agent_id="11111111-1111-1111-1111-111111111111",
            user_id=2,
            user_email="alice@example.com",
            machine_name="alice-laptop",
            client_version="0.4.0",
            created_at=datetime(2026, 4, 26, 12, 0, tzinfo=UTC),
            last_seen_at=datetime(2026, 4, 26, 12, 30, tzinfo=UTC),
            revoked_at=None,
        ),
        auth_client.AdminAgentItem(
            agent_id="22222222-2222-2222-2222-222222222222",
            user_id=3,
            user_email="bob@example.com",
            machine_name="bob-laptop",
            client_version="0.4.0",
            created_at=datetime(2026, 4, 26, 13, 0, tzinfo=UTC),
            last_seen_at=None,
            revoked_at=datetime(2026, 4, 26, 14, 0, tzinfo=UTC),
        ),
    ]
    items = base[:count]
    return items, total if total is not None else len(items)


# ---------------------------------------------------------------------------
# GET /admin/agents — admin sees every agent across every user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_admin_agents_lists_all_agents_for_admin(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AdminAgentItem], int]:
        return _sample_agents()

    monkeypatch.setattr(auth_client, "admin_list_agents", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # Every owner email is rendered — i.e. cross-user view, not just self.
    assert "alice@example.com" in r.text
    assert "bob@example.com" in r.text
    # Each owner email links to the user's anchor on /admin/users.
    assert "/admin/users#user-2" in r.text
    assert "/admin/users#user-3" in r.text
    # Active agent has a revoke action; revoked agent does not.
    assert "/admin/agents/11111111-1111-1111-1111-111111111111/revoke" in r.text
    assert "/admin/agents/22222222-2222-2222-2222-222222222222/revoke" not in r.text


@pytest.mark.asyncio
async def test_get_admin_agents_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_admin_agents_unauth_redirects(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/admin/agents")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_get_admin_agents_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_list_agents", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_get_admin_agents_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_list_agents", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Pagination — same shape as /admin/users (?page= & per_page=)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_admin_agents_passes_pagination_to_auth_client(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AdminAgentItem], int]:
        captured["limit"] = limit
        captured["offset"] = offset
        return [], 0

    monkeypatch.setattr(auth_client, "admin_list_agents", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents?page=3&per_page=25")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert captured == {"limit": 25, "offset": 50}


@pytest.mark.asyncio
async def test_get_admin_agents_renders_next_link_when_more_pages(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AdminAgentItem], int]:
        items, _ = _sample_agents()
        return items, 250

    monkeypatch.setattr(auth_client, "admin_list_agents", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents?page=1&per_page=2")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "page=2" in r.text
    assert "Next" in r.text
    assert "page=0" not in r.text


@pytest.mark.asyncio
async def test_get_admin_agents_renders_prev_link_on_later_page(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AdminAgentItem], int]:
        items, _ = _sample_agents(count=1)
        return items, 3

    monkeypatch.setattr(auth_client, "admin_list_agents", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents?page=2&per_page=2")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "page=1" in r.text
    assert "Previous" in r.text
    assert "Next" not in r.text


@pytest.mark.asyncio
async def test_get_admin_agents_rejects_per_page_above_ceiling(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/agents?per_page=500")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /admin/agents/{id}/revoke — revoke any agent regardless of ownership
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_revoke_agent_success_redirects(
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

    monkeypatch.setattr(auth_client, "admin_revoke_agent", fake_revoke)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    agent_id = "11111111-1111-1111-1111-111111111111"
    try:
        r = await app_client.post(f"/admin/agents/{agent_id}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].startswith("/admin/agents")
    # Agent ID is forwarded verbatim — no per-row ownership scoping
    # at the web layer (revoke-any is the spec).
    assert captured["agent_id"] == agent_id


@pytest.mark.asyncio
async def test_post_revoke_agent_admin_can_revoke_any_owner(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admin (user_id=1) revokes an agent owned by user_id=2 — no
    self-only short-circuit on the web layer."""
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    seen: dict[str, Any] = {}

    async def fake_revoke(_url: str, _token: str, agent_id: str) -> tuple[bool, str | None]:
        seen["called_with"] = agent_id
        return True, None

    monkeypatch.setattr(auth_client, "admin_revoke_agent", fake_revoke)
    dep, _ = _override_admin(user_id=1)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    other_user_agent = "11111111-1111-1111-1111-111111111111"
    try:
        r = await app_client.post(f"/admin/agents/{other_user_agent}/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert seen["called_with"] == other_user_agent


@pytest.mark.asyncio
async def test_post_revoke_agent_not_found_renders_inline_404(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_revoke(*_a: Any, **_kw: Any) -> tuple[bool, str | None]:
        return False, "agent_not_found"

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AdminAgentItem], int]:
        return _sample_agents()

    monkeypatch.setattr(auth_client, "admin_revoke_agent", fake_revoke)
    monkeypatch.setattr(auth_client, "admin_list_agents", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/agents/00000000-0000-0000-0000-000000000000/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert "no longer exists" in r.text.lower()


@pytest.mark.asyncio
async def test_post_revoke_agent_503_when_auth_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthClientError("simulated outage")

    monkeypatch.setattr(auth_client, "admin_revoke_agent", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/agents/11111111-1111-1111-1111-111111111111/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_post_revoke_agent_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/agents/11111111-1111-1111-1111-111111111111/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_revoke_agent_admin_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise auth_client.AuthForbidden("simulated demotion")

    monkeypatch.setattr(auth_client, "admin_revoke_agent", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/agents/11111111-1111-1111-1111-111111111111/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_post_revoke_agent_rejects_malformed_uuid(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/agents/not-a-uuid/revoke")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 422


# ---------------------------------------------------------------------------
# End-to-end flow — admin lists, revokes, refreshes shows it gone
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_list_revoke_refresh_flow(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Integration-style flow against an in-memory fake auth backend.

    1) GET /admin/agents lists 2 active agents.
    2) POST /admin/agents/{id}/revoke marks one as revoked (303 back).
    3) Follow-up GET shows that agent's row no longer offers a revoke
       action, while the other still does.
    """
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    items, _ = _sample_agents()
    # Reset to an all-active starting state — the second sample is
    # already revoked, but we want both fresh for this flow.
    items[1] = auth_client.AdminAgentItem(
        agent_id=items[1].agent_id,
        user_id=items[1].user_id,
        user_email=items[1].user_email,
        machine_name=items[1].machine_name,
        client_version=items[1].client_version,
        created_at=items[1].created_at,
        last_seen_at=items[1].last_seen_at,
        revoked_at=None,
    )
    state = {"items": items}

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.AdminAgentItem], int]:
        return state["items"], len(state["items"])

    async def fake_revoke(_url: str, _token: str, agent_id: str) -> tuple[bool, str | None]:
        for i, a in enumerate(state["items"]):
            if a.agent_id == agent_id and a.revoked_at is None:
                state["items"][i] = auth_client.AdminAgentItem(
                    agent_id=a.agent_id,
                    user_id=a.user_id,
                    user_email=a.user_email,
                    machine_name=a.machine_name,
                    client_version=a.client_version,
                    created_at=a.created_at,
                    last_seen_at=a.last_seen_at,
                    revoked_at=datetime(2026, 4, 26, 15, 0, tzinfo=UTC),
                )
                return True, None
        return False, "agent_not_found"

    monkeypatch.setattr(auth_client, "admin_list_agents", fake_list)
    monkeypatch.setattr(auth_client, "admin_revoke_agent", fake_revoke)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep

    target = items[0].agent_id
    try:
        r1 = await app_client.get("/admin/agents")
        assert r1.status_code == 200
        assert f"/admin/agents/{target}/revoke" in r1.text

        r2 = await app_client.post(f"/admin/agents/{target}/revoke")
        assert r2.status_code == 303

        r3 = await app_client.get("/admin/agents")
        assert r3.status_code == 200
        # Active row's revoke action is gone; the other agent's
        # revoke action is still present.
        assert f"/admin/agents/{target}/revoke" not in r3.text
        assert f"/admin/agents/{items[1].agent_id}/revoke" in r3.text
    finally:
        _main.app.dependency_overrides.clear()
