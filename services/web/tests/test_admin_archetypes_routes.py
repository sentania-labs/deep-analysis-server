"""Web admin route tests for the archetype catalog.

Mirrors the structure of ``test_admin_routes.py`` (the admin user
tests) — bypasses browser auth via FastAPI dependency overrides and
patches ``analytics_client`` so we can focus on handler behavior +
client wiring.
"""

from __future__ import annotations

import uuid
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


def _override_non_admin() -> Any:
    from web_service import deps as _deps

    fake_user = _deps.BrowserUser(
        user_id=42,
        email="u@example.com",
        role="user",
        must_change_password=False,
        scope=None,
        token="user-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_user

    return _dep, fake_user


def _sample_archetype(name: str = "Burn") -> Any:
    from web_service import analytics_client

    return analytics_client.ArchetypeItem(
        id=str(uuid.uuid4()),
        name=name,
        format="Modern",
        defining_cards=["Lightning Bolt", "Goblin Guide"],
        sample_decklists=None,
        created_at=datetime(2026, 5, 9, 12, 0, tzinfo=UTC),
        updated_at=datetime(2026, 5, 9, 12, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# GET /admin/archetypes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_archetypes_lists_for_admin(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    items = [_sample_archetype("Burn"), _sample_archetype("Tron")]

    async def fake_list(_url: str, _token: str) -> tuple[list[Any], int]:
        return items, 2

    monkeypatch.setattr(analytics_client, "admin_list_archetypes", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/archetypes")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Burn" in r.text
    assert "Tron" in r.text
    assert "/admin/archetypes/new" in r.text


@pytest.mark.asyncio
async def test_get_archetypes_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/archetypes")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_archetypes_unauth_redirects(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/admin/archetypes")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_get_archetypes_503_when_analytics_unreachable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "admin_list_archetypes", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/archetypes")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


# ---------------------------------------------------------------------------
# GET /admin/archetypes/new
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_new_form_renders_for_admin(app_client: httpx.AsyncClient) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/archetypes/new")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "<form" in r.text
    assert 'name="name"' in r.text
    assert 'name="format"' in r.text
    assert 'name="defining_cards"' in r.text


# ---------------------------------------------------------------------------
# POST /admin/archetypes/create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_create_succeeds_and_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_create(
        _url: str,
        _token: str,
        *,
        name: str,
        format_: str,
        defining_cards: list[str],
    ) -> tuple[Any, str | None]:
        captured["name"] = name
        captured["format"] = format_
        captured["defining_cards"] = defining_cards
        return _sample_archetype(name=name), None

    monkeypatch.setattr(analytics_client, "admin_create_archetype", fake_create)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/archetypes/create",
            data={
                "name": "Burn",
                "format": "Modern",
                "defining_cards": "Lightning Bolt\nGoblin Guide\n\n  Lava Spike  ",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].endswith("/admin/archetypes")
    assert captured["name"] == "Burn"
    assert captured["format"] == "Modern"
    # Whitespace and blank lines should have been stripped, order preserved.
    assert captured["defining_cards"] == ["Lightning Bolt", "Goblin Guide", "Lava Spike"]


@pytest.mark.asyncio
async def test_post_create_rejects_blank_name(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/archetypes/create",
            data={
                "name": "   ",
                "format": "Modern",
                "defining_cards": "Lightning Bolt",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 400
    assert "required" in r.text.lower()


@pytest.mark.asyncio
async def test_post_create_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            "/admin/archetypes/create",
            data={"name": "Burn", "format": "Modern", "defining_cards": ""},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /admin/archetypes/{id}/edit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_edit_form_pre_fills_existing_data(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    item = _sample_archetype("Murktide")

    async def fake_get(_url: str, _token: str, archetype_id: str) -> Any:
        assert archetype_id == item.id
        return item

    monkeypatch.setattr(analytics_client, "admin_get_archetype", fake_get)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get(f"/admin/archetypes/{item.id}/edit")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Murktide" in r.text
    assert "Lightning Bolt" in r.text


@pytest.mark.asyncio
async def test_get_edit_form_404_when_archetype_missing(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_get(_url: str, _token: str, _archetype_id: str) -> Any:
        return None

    monkeypatch.setattr(analytics_client, "admin_get_archetype", fake_get)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get(f"/admin/archetypes/{uuid.uuid4()}/edit")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /admin/archetypes/{id}/edit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_edit_succeeds_and_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    item = _sample_archetype("Burn")
    captured: dict[str, Any] = {}

    async def fake_update(
        _url: str,
        _token: str,
        archetype_id: str,
        *,
        name: str,
        format_: str,
        defining_cards: list[str],
    ) -> tuple[Any, str | None]:
        captured["id"] = archetype_id
        captured["name"] = name
        captured["defining_cards"] = defining_cards
        return item, None

    monkeypatch.setattr(analytics_client, "admin_update_archetype", fake_update)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            f"/admin/archetypes/{item.id}/edit",
            data={
                "name": "Burn",
                "format": "Modern",
                "defining_cards": "Lightning Bolt\nGoblin Guide",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].endswith("/admin/archetypes")
    assert captured["id"] == item.id
    assert captured["defining_cards"] == ["Lightning Bolt", "Goblin Guide"]


@pytest.mark.asyncio
async def test_post_edit_handles_not_found_inline(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_update(*_a: Any, **_kw: Any) -> tuple[Any, str | None]:
        return None, "archetype_not_found"

    monkeypatch.setattr(analytics_client, "admin_update_archetype", fake_update)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(
            f"/admin/archetypes/{uuid.uuid4()}/edit",
            data={"name": "Burn", "format": "Modern", "defining_cards": ""},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert "no longer exists" in r.text.lower()


# ---------------------------------------------------------------------------
# POST /admin/archetypes/{id}/delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_delete_succeeds_and_redirects(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_delete(_url: str, _token: str, archetype_id: str) -> tuple[bool, str | None]:
        captured["id"] = archetype_id
        return True, None

    monkeypatch.setattr(analytics_client, "admin_delete_archetype", fake_delete)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        target = uuid.uuid4()
        r = await app_client.post(f"/admin/archetypes/{target}/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert r.headers["location"].endswith("/admin/archetypes")
    assert captured["id"] == str(target)


@pytest.mark.asyncio
async def test_post_delete_propagates_not_found_inline(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(_url: str, _token: str) -> tuple[list[Any], int]:
        return [], 0

    async def fake_delete(*_a: Any, **_kw: Any) -> tuple[bool, str | None]:
        return False, "archetype_not_found"

    monkeypatch.setattr(analytics_client, "admin_list_archetypes", fake_list)
    monkeypatch.setattr(analytics_client, "admin_delete_archetype", fake_delete)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(f"/admin/archetypes/{uuid.uuid4()}/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert "no longer exists" in r.text.lower()


@pytest.mark.asyncio
async def test_post_delete_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_non_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post(f"/admin/archetypes/{uuid.uuid4()}/delete")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


# ---------------------------------------------------------------------------
# AnalyticsForbidden — analytics rejected the call. Should render 403,
# not 503.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_archetypes_analytics_forbidden_renders_403(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsForbidden("demoted mid-session")

    monkeypatch.setattr(analytics_client, "admin_list_archetypes", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/admin/archetypes")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403
