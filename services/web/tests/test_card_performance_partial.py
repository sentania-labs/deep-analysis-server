"""Tests for the sortable Card Performance HTMX partial.

Covers the route-level query-param validation, the analytics_client
sort_dir round-trip, and the template's clickable headers + indicator
arrows + pagination URL preservation.
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


def _sample_card_stats() -> Any:
    from web_service import analytics_client

    return analytics_client.CardStatsResponse(
        cards=[
            analytics_client.CardStatItem(
                card_name="Lightning Bolt",
                games=10,
                wins=6,
                win_rate=60.0,
                avg_cast_turn=2.5,
            ),
            analytics_client.CardStatItem(
                card_name="Mountain",
                games=20,
                wins=12,
                win_rate=60.0,
                avg_cast_turn=None,
            ),
        ],
        total=22,
        page=1,
        per_page=10,
    )


# ---------------------------------------------------------------------------
# Query-param round-trip + validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_passes_sort_and_dir_through_to_analytics_client(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_card_stats(_url: str, _token: str, **kw: Any) -> Any:
        captured.update(kw)
        return _sample_card_stats()

    monkeypatch.setattr(analytics_client, "get_card_stats", fake_card_stats)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/dashboard/partials/card-performance",
            params={"sort": "win_rate", "dir": "asc", "format": "Modern", "page": 2},
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert captured["sort_by"] == "win_rate"
    assert captured["sort_dir"] == "asc"
    assert captured["format_filter"] == "Modern"
    assert captured["page"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("params", "expected_sort", "expected_dir"),
    [
        # Invalid sort → games. Valid dir is preserved.
        ({"sort": "wins", "dir": "asc"}, "games", "asc"),
        # Invalid dir → desc. Valid sort is preserved.
        ({"sort": "win_rate", "dir": "sideways"}, "win_rate", "desc"),
        # Both invalid → both defaults.
        ({"sort": "DROP TABLE", "dir": "down"}, "games", "desc"),
        # No params at all → defaults.
        ({}, "games", "desc"),
    ],
)
async def test_partial_invalid_sort_or_dir_falls_back_to_defaults(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    params: dict[str, str],
    expected_sort: str,
    expected_dir: str,
) -> None:
    """User clicked something we don't recognize → render with defaults, not 400."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    captured: dict[str, Any] = {}

    async def fake_card_stats(_url: str, _token: str, **kw: Any) -> Any:
        captured.update(kw)
        return _sample_card_stats()

    monkeypatch.setattr(analytics_client, "get_card_stats", fake_card_stats)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard/partials/card-performance", params=params)
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert captured["sort_by"] == expected_sort
    assert captured["sort_dir"] == expected_dir


# ---------------------------------------------------------------------------
# Template rendering — header URLs, indicators, pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_renders_clickable_headers_with_correct_urls(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each header issues an hx-get that flips/sets sort state correctly."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_card_stats(_url: str, _token: str, **_kw: Any) -> Any:
        return _sample_card_stats()

    monkeypatch.setattr(analytics_client, "get_card_stats", fake_card_stats)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        # Currently sorted by games desc.
        r = await app_client.get(
            "/dashboard/partials/card-performance",
            params={"sort": "games", "dir": "desc"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    html = r.text
    # Inactive headers point at their natural default direction.
    assert "sort=card_name&amp;dir=asc" in html
    assert "sort=win_rate&amp;dir=desc" in html
    assert "sort=avg_cast_turn&amp;dir=desc" in html
    # The active header (games) toggles to asc.
    assert "sort=games&amp;dir=asc" in html
    # Toggling sort always resets to page 1.
    assert "page=1&amp;sort=games" in html


@pytest.mark.asyncio
async def test_partial_shows_indicator_only_on_active_column(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_card_stats(_url: str, _token: str, **_kw: Any) -> Any:
        return _sample_card_stats()

    monkeypatch.setattr(analytics_client, "get_card_stats", fake_card_stats)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r_desc = await app_client.get(
            "/dashboard/partials/card-performance",
            params={"sort": "win_rate", "dir": "desc"},
        )
        r_asc = await app_client.get(
            "/dashboard/partials/card-performance",
            params={"sort": "win_rate", "dir": "asc"},
        )
    finally:
        _main.app.dependency_overrides.clear()

    # desc → ↓, asc → ↑. Only one arrow each.
    assert r_desc.text.count("&darr;") == 1
    assert "&uarr;" not in r_desc.text
    assert r_asc.text.count("&uarr;") == 1
    assert "&darr;" not in r_asc.text
    # aria-sort marks the active column.
    assert 'aria-sort="descending"' in r_desc.text
    assert 'aria-sort="ascending"' in r_asc.text


@pytest.mark.asyncio
async def test_partial_pagination_preserves_sort_and_dir(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_card_stats(_url: str, _token: str, **_kw: Any) -> Any:
        # Force a second page to exist by claiming total > per_page.
        return analytics_client.CardStatsResponse(
            cards=[
                analytics_client.CardStatItem(
                    card_name="Bolt",
                    games=1,
                    wins=1,
                    win_rate=100.0,
                    avg_cast_turn=1.0,
                ),
            ],
            total=30,
            page=2,
            per_page=10,
        )

    monkeypatch.setattr(analytics_client, "get_card_stats", fake_card_stats)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/dashboard/partials/card-performance",
            params={"sort": "win_rate", "dir": "asc", "page": 2},
        )
    finally:
        _main.app.dependency_overrides.clear()

    html = r.text
    # Both Prev and Next URLs carry the active sort/dir.
    assert "sort=win_rate&amp;dir=asc&amp;page=1" in html
    assert "sort=win_rate&amp;dir=asc&amp;page=3" in html


# ---------------------------------------------------------------------------
# analytics_client wire-level sort_dir round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analytics_client_get_card_stats_sends_sort_dir() -> None:
    from web_service import analytics_client

    captured_urls: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_urls.append(request.url)
        return httpx.Response(200, json={"cards": [], "total": 0, "page": 1, "per_page": 10})

    transport = httpx.MockTransport(handler)

    # Patch httpx.AsyncClient inside the client module to use our transport.
    import httpx as _httpx_mod

    original = _httpx_mod.AsyncClient

    class _PatchedClient(_httpx_mod.AsyncClient):
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = transport
            super().__init__(*a, **kw)

    _httpx_mod.AsyncClient = _PatchedClient  # type: ignore[misc]
    try:
        await analytics_client.get_card_stats(
            "http://analytics:8000",
            "tok",
            sort_by="win_rate",
            sort_dir="asc",
            format_filter="Modern",
        )
    finally:
        _httpx_mod.AsyncClient = original  # type: ignore[misc]

    assert len(captured_urls) == 1
    url = captured_urls[0]
    params = dict(url.params)
    assert params["sort_by"] == "win_rate"
    assert params["sort_dir"] == "asc"
    assert params["format"] == "Modern"


@pytest.mark.asyncio
async def test_analytics_client_omits_sort_dir_when_none() -> None:
    """``sort_dir=None`` lets the analytics service apply its column-default."""
    from web_service import analytics_client

    captured_urls: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_urls.append(request.url)
        return httpx.Response(200, json={"cards": [], "total": 0, "page": 1, "per_page": 10})

    transport = httpx.MockTransport(handler)
    import httpx as _httpx_mod

    original = _httpx_mod.AsyncClient

    class _PatchedClient(_httpx_mod.AsyncClient):
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = transport
            super().__init__(*a, **kw)

    _httpx_mod.AsyncClient = _PatchedClient  # type: ignore[misc]
    try:
        await analytics_client.get_card_stats(
            "http://analytics:8000",
            "tok",
            sort_by="card_name",
        )
    finally:
        _httpx_mod.AsyncClient = original  # type: ignore[misc]

    params = dict(captured_urls[0].params)
    assert params["sort_by"] == "card_name"
    assert "sort_dir" not in params
