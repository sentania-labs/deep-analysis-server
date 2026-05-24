"""Web-layer tests for the user-scope reparse routes.

Covers:
- POST /admin/users/{user_id}/reparse  — admin user-scope (no rate limit)
- POST /profile/reparse                — user self-service (rate limited)

Web-layer auth is bypassed via FastAPI dependency overrides; the
parser_client is monkeypatched so we exercise the handler + template
wiring without standing up a parser process.

The rate-limit *logic* itself lives in the parser service and is
exercised in services/parser/tests/test_reparse_routes.py against a
real Postgres.
"""

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


def _override_user(user_id: int = 42, token: str = "user-tok") -> Any:
    from web_service import deps as _deps

    fake_user = _deps.BrowserUser(
        user_id=user_id,
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
# Admin user-scope reparse: POST /admin/users/{user_id}/reparse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_user_reparse_success(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import auth_client, parser_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_delete(
        _url: str, _token: str, user_id: int, *, agent_id: str | None = None
    ) -> parser_client.DeletedCountResult:
        captured["user_id"] = user_id
        captured["agent_id"] = agent_id
        return parser_client.DeletedCountResult(deleted_count=11)

    async def fake_list(
        _url: str, _token: str, limit: int = 50, offset: int = 0
    ) -> tuple[list[auth_client.UserItem], int]:
        return [], 0

    monkeypatch.setattr(parser_client, "admin_delete_user_matches", fake_delete)
    monkeypatch.setattr(auth_client, "admin_list_users", fake_list)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/7/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert captured["user_id"] == 7
    assert captured["agent_id"] is None
    # Success banner is rendered on the admin users page.
    assert "Reparse complete for user #7" in r.text
    assert "11 matches deleted" in r.text


@pytest.mark.asyncio
async def test_admin_user_reparse_forbidden_for_non_admin(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/7/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_user_reparse_503_when_parser_unreachable(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main
    from web_service import parser_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise parser_client.ParserClientError("simulated outage")

    monkeypatch.setattr(parser_client, "admin_delete_user_matches", boom)
    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/admin/users/7/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


# ---------------------------------------------------------------------------
# User self-service reparse: POST /profile/reparse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_profile_reparse_success(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import auth_client, parser_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_self(_url: str, _token: str) -> parser_client.DeletedCountResult:
        return parser_client.DeletedCountResult(deleted_count=3)

    async def fake_me(_url: str, _token: str) -> auth_client.MeResult:
        return auth_client.MeResult(
            user_id=42, email="u@example.com", role="user", must_change_password=False
        )

    monkeypatch.setattr(parser_client, "user_self_service_reparse", fake_self)
    monkeypatch.setattr(auth_client, "get_me", fake_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Reparse complete" in r.text
    assert "3 matches deleted" in r.text


@pytest.mark.asyncio
async def test_profile_reparse_rate_limited_renders_friendly_message(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On 429 from parser, the profile page should render with a
    user-facing 'Try again at HH:MM' message — not a 503 outage page."""
    from web_service import auth_client, parser_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_self(_url: str, _token: str) -> parser_client.DeletedCountResult:
        raise parser_client.ParserRateLimited(
            retry_after_seconds=1800,
            retry_at="2026-05-24T15:30:00+00:00",
        )

    async def fake_me(_url: str, _token: str) -> auth_client.MeResult:
        return auth_client.MeResult(
            user_id=42, email="u@example.com", role="user", must_change_password=False
        )

    monkeypatch.setattr(parser_client, "user_self_service_reparse", fake_self)
    monkeypatch.setattr(auth_client, "get_me", fake_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 429
    assert "Already reparsed within the last hour" in r.text
    assert "15:30 UTC" in r.text


@pytest.mark.asyncio
async def test_profile_reparse_admin_bounced(app_client: httpx.AsyncClient) -> None:
    """Admins have no /profile/* surface — should bounce to admin panel."""
    from web_service import deps as _deps
    from web_service import main as _main

    dep, _ = _override_admin()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    # 302 redirect to the admin landing page.
    assert r.status_code == 302


@pytest.mark.asyncio
async def test_profile_reparse_503_when_parser_unreachable(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main
    from web_service import parser_client

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise parser_client.ParserClientError("simulated outage")

    monkeypatch.setattr(parser_client, "user_self_service_reparse", boom)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.post("/profile/reparse")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_profile_renders_reparse_button_and_modal(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The /profile page should surface the Reparse button + Alpine modal."""
    from web_service import auth_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_me(_url: str, _token: str) -> auth_client.MeResult:
        return auth_client.MeResult(
            user_id=42, email="u@example.com", role="user", must_change_password=False
        )

    monkeypatch.setattr(auth_client, "get_me", fake_me)
    dep, _ = _override_user()
    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/profile")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Reparse my matches" in r.text
    # The modal body text — at least one distinctive phrase.
    assert "This won&#39;t fix" in r.text or "This won't fix" in r.text
    # The form posts to the new endpoint.
    assert 'action="/profile/reparse"' in r.text
