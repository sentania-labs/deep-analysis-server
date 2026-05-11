"""Tests for the user-facing /cards search route.

Bypasses browser auth via FastAPI dependency overrides and patches the
analytics client so we can exercise template rendering, the empty
search form, the empty-results path, and the error-banner branch
without a live analytics service.
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


def _override_user(user_id: int = 42, token: str = "user-tok") -> Any:
    from web_service import deps as _deps

    fake_user = _deps.BrowserUser(
        user_id=user_id,
        email="alice@example.com",
        role="user",
        must_change_password=False,
        scope=None,
        token=token,
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_user

    return _dep


def _sample_card(name: str = "Lightning Bolt", with_image: bool = True) -> Any:
    from web_service import analytics_client

    return analytics_client.CardItem(
        name=name,
        mana_cost="{R}",
        type_line="Instant",
        oracle_text="Lightning Bolt deals 3 damage to any target.",
        image_uri="https://example/lb.jpg" if with_image else None,
        set_code="lea",
    )


@pytest.mark.asyncio
async def test_cards_blank_query_renders_form_only(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:  # would-be analytics call
        raise AssertionError("search_cards should not be called for blank query")

    monkeypatch.setattr(analytics_client, "search_cards", boom)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/cards")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Card Search" in r.text
    assert "Search card name" in r.text
    assert "No cards found" not in r.text


@pytest.mark.asyncio
async def test_cards_search_renders_results(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    seen: dict[str, Any] = {}

    async def fake_search(_url: str, _token: str, q: str) -> Any:
        seen["q"] = q
        return [_sample_card(), _sample_card(name="Lightning Strike", with_image=False)]

    monkeypatch.setattr(analytics_client, "search_cards", fake_search)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/cards", params={"q": "Lightning"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert seen["q"] == "Lightning"
    text = r.text
    assert "Lightning Bolt" in text
    assert "Lightning Strike" in text
    assert "https://example/lb.jpg" in text
    assert "Search unavailable" not in text


@pytest.mark.asyncio
async def test_cards_search_no_results_message(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_search(_url: str, _token: str, _q: str) -> Any:
        return []

    monkeypatch.setattr(analytics_client, "search_cards", fake_search)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/cards", params={"q": "zzznosuch"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "No cards found" in r.text


@pytest.mark.asyncio
async def test_cards_search_error_banner_on_analytics_failure(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "search_cards", boom)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/cards", params={"q": "Bolt"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Search unavailable" in r.text


@pytest.mark.asyncio
async def test_cards_unauth_redirects_to_login(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get("/cards")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")
