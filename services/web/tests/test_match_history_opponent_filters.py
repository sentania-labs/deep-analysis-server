"""Match History opponent aggregates must honour the active filters (#124).

The page used to call ``/analytics/stats/by-opponent`` with no arguments, so a
filtered match list sat next to all-time opponent numbers with nothing saying
the two halves disagreed. These tests pin the route down to forwarding the same
filters it sends to the match list, and pin the client down to putting them on
the wire.
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


def _override_player() -> Any:
    from web_service import deps as _deps

    player = _deps.BrowserUser(
        user_id=42,
        email="alice@local",
        role="user",
        must_change_password=False,
        scope=None,
        token="player-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return player

    return _dep


def _empty_match_list() -> Any:
    from web_service import analytics_client

    return analytics_client.MatchListResponse(matches=[], total=0, page=1, per_page=20)


async def _render(app_client: httpx.AsyncClient, monkeypatch: Any, url: str) -> dict[str, Any]:
    """Render ``url`` and return the kwargs the two analytics calls received."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    seen: dict[str, Any] = {}

    async def fake_match_list(*_a: Any, **kw: Any) -> Any:
        seen["match_list"] = kw
        return _empty_match_list()

    async def fake_by_opponent(*_a: Any, **kw: Any) -> Any:
        seen["by_opponent"] = kw
        return []

    monkeypatch.setattr(analytics_client, "get_match_list", fake_match_list)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_by_opponent)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_player()
    try:
        r = await app_client.get(url)
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 200, r.text
    return seen


@pytest.mark.asyncio
async def test_filters_reach_the_opponent_aggregates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = await _render(
        app_client,
        monkeypatch,
        "/matches?format=Modern&opponent=bob&result=wins&date_from=2026-05-01&date_to=2026-05-31",
    )

    assert seen["by_opponent"] == {
        "format_filter": "Modern",
        "opponent": "bob",
        "result": "wins",
        "date_from": "2026-05-01",
        "date_to": "2026-05-31",
    }


@pytest.mark.asyncio
async def test_opponent_aggregates_see_the_same_filters_as_the_match_list(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two halves of the page must describe the same set of matches."""
    seen = await _render(
        app_client,
        monkeypatch,
        "/matches?format=Pauper&date_from=2026-04-01",
    )

    shared = ("format_filter", "opponent", "result", "date_from", "date_to")
    for key in shared:
        assert seen["by_opponent"][key] == seen["match_list"][key], key


@pytest.mark.asyncio
async def test_unfiltered_page_sends_no_filters(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = await _render(app_client, monkeypatch, "/matches")

    assert seen["by_opponent"] == {
        "format_filter": None,
        "opponent": None,
        "result": None,
        "date_from": None,
        "date_to": None,
    }


# ---------------------------------------------------------------------------
# Client: filters have to make it onto the query string
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_puts_filters_on_the_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client

    seen: dict[str, Any] = {}

    class _Resp:
        @staticmethod
        def json() -> list[Any]:
            return []

    async def fake_request(_method: str, url: str, **kw: Any) -> Any:
        seen["url"] = url
        seen["params"] = kw.get("params")
        return _Resp()

    monkeypatch.setattr(analytics_client, "request", fake_request)

    await analytics_client.get_stats_by_opponent(
        "http://analytics",
        "tok",
        format_filter="Modern",
        opponent="bob",
        result="wins",
        date_from="2026-05-01",
        date_to="2026-05-31",
    )

    assert seen["url"] == "http://analytics/analytics/stats/by-opponent"
    assert seen["params"] == {
        "format": "Modern",
        "opponent": "bob",
        "result": "wins",
        "date_from": "2026-05-01",
        "date_to": "2026-05-31",
    }


@pytest.mark.asyncio
async def test_client_drops_all_sentinels_and_blanks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``all`` is the template's "no filter" option, same as ``get_match_list``."""
    from web_service import analytics_client

    seen: dict[str, Any] = {}

    class _Resp:
        @staticmethod
        def json() -> list[Any]:
            return []

    async def fake_request(_method: str, _url: str, **kw: Any) -> Any:
        seen["params"] = kw.get("params")
        return _Resp()

    monkeypatch.setattr(analytics_client, "request", fake_request)

    await analytics_client.get_stats_by_opponent(
        "http://analytics",
        "tok",
        format_filter="all",
        opponent="",
        result="all",
    )

    assert seen["params"] == {}
