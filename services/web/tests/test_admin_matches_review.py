"""Tests for the holding-pen admin actions on /admin/matches.

Covers:

* The list template renders the review_status badge (Pending review /
  Rejected) and the action buttons appropriate to each row's state.
* The chip filter passes ``review_status`` through to the analytics
  client.
* POST /admin/matches/{id}/review forwards the verdict to the analytics
  client and redirects on success.
* Invalid verdict values 422 instead of silently no-op.
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


def _override_admin(user_id: int = 1) -> Any:
    from web_service import deps as _deps

    fake_admin = _deps.BrowserUser(
        user_id=user_id,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_admin

    return _dep


def _matches_response(review_statuses: list[str | None]) -> Any:
    """Build a fake AdminMatchListResponse with one row per status."""
    from web_service import analytics_client

    items = []
    for idx, rs in enumerate(review_statuses, start=1):
        items.append(
            analytics_client.AdminMatchItem(
                match_id=f"00000000-0000-0000-0000-{idx:012d}",
                user_id=42,
                user_email="alice@local",
                format_="Modern",
                players=["alice", "bob"],
                match_result="2-0" if rs is None else None,
                winner="alice" if rs is None else None,
                game_count=2,
                played_at=datetime(2026, 5, 22, 12, 0, tzinfo=UTC),
                is_draw=False,
                review_status=rs,
            )
        )
    return analytics_client.AdminMatchListResponse(
        matches=items,
        total=len(items),
        page=1,
        per_page=20,
    )


@pytest.mark.asyncio
async def test_admin_matches_renders_review_status_badges(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_list(*_a: Any, **_kw: Any) -> Any:
        return _matches_response([None, "pending_review", "rejected"])

    monkeypatch.setattr(analytics_client, "admin_list_matches", fake_list)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/matches")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.text
    assert "Pending review" in body
    assert "Rejected" in body
    # Action buttons appropriate to each row's state.
    assert "Accept" in body
    assert "Reject" in body
    assert "Restore" in body
    assert "Flag" in body


@pytest.mark.asyncio
async def test_admin_matches_chip_filter_propagates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``?review_status=pending_review`` chip filter must reach the
    analytics client as ``review_status='pending_review'``."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_list(*args: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return _matches_response(["pending_review"])

    monkeypatch.setattr(analytics_client, "admin_list_matches", fake_list)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/matches?review_status=pending_review")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert captured.get("review_status") == "pending_review"


@pytest.mark.asyncio
async def test_post_review_accept_calls_client_with_none(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept (verdict="") posts ``review_status=None`` to analytics."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_set(
        _base_url: str,
        _token: str,
        match_id: str,
        review_status: str | None,
    ) -> tuple[Any, str | None]:
        captured["match_id"] = match_id
        captured["review_status"] = review_status
        item = analytics_client.AdminMatchItem(
            match_id=match_id,
            user_id=42,
            user_email="alice@local",
            format_="Modern",
            players=["alice", "bob"],
            match_result="2-0",
            winner="alice",
            game_count=2,
            played_at=datetime(2026, 5, 22, 12, 0, tzinfo=UTC),
            is_draw=False,
            review_status=review_status,
        )
        return item, None

    monkeypatch.setattr(analytics_client, "admin_set_match_review_status", fake_set)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post(
            "/admin/matches/00000000-0000-0000-0000-000000000001/review",
            data={"verdict": "", "return_to": "/admin/matches"},
            follow_redirects=False,
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert captured["match_id"] == "00000000-0000-0000-0000-000000000001"
    assert captured["review_status"] is None
    # The success message is encoded into the redirect URL.
    assert "Match+accepted" in r.headers["location"]


@pytest.mark.asyncio
async def test_post_review_reject_passes_string_through(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_set(
        _base_url: str,
        _token: str,
        match_id: str,
        review_status: str | None,
    ) -> tuple[Any, str | None]:
        captured["review_status"] = review_status
        item = analytics_client.AdminMatchItem(
            match_id=match_id,
            user_id=42,
            user_email="alice@local",
            format_=None,
            players=[],
            match_result=None,
            winner=None,
            game_count=0,
            played_at=None,
            is_draw=False,
            review_status=review_status,
        )
        return item, None

    monkeypatch.setattr(analytics_client, "admin_set_match_review_status", fake_set)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post(
            "/admin/matches/00000000-0000-0000-0000-000000000002/review",
            data={"verdict": "rejected"},
            follow_redirects=False,
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 303
    assert captured["review_status"] == "rejected"


@pytest.mark.asyncio
async def test_post_review_invalid_verdict_returns_422(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.post(
            "/admin/matches/00000000-0000-0000-0000-000000000003/review",
            data={"verdict": "totally-bogus"},
        )
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_admin_matches_unknown_review_status_filter_falls_back(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown ``review_status`` chip value falls back to "all" rather
    than 422'ing the page — the chip UI can't get to an invalid value
    via clicks, but a hand-crafted URL shouldn't crash."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_list(*_a: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return _matches_response([None])

    monkeypatch.setattr(analytics_client, "admin_list_matches", fake_list)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/matches?review_status=bogus")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # Unknown filter sanitized to None, so the analytics call doesn't
    # receive a review_status param.
    assert captured.get("review_status") is None
