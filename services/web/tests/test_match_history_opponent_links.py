"""Opponent drill-down links must preserve the active filters (#133).

The three opponent link sites on Match History (match rows, Top Opponents,
By opponent) used to navigate to a bare ``/matches?opponent=...``, which
dropped the format/result/date filters the user was reading and silently
widened the numbers to all-time, all-format.
"""

from __future__ import annotations

import html
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio

MATCH_ROW_OPPONENT = "bob & jones"
STATS_OPPONENT = "carol & dave"
#: Sits past the first opponent page, so a link can be checked while the
#: By opponent table is showing opp_page=2.
PAGE2_OPPONENT = "zeta filler 21"


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


def _match_list() -> Any:
    from web_service import analytics_client

    return analytics_client.MatchListResponse(
        matches=[
            analytics_client.MatchListItem(
                match_id="00000000-0000-0000-0000-000000000001",
                played_at=datetime(2026, 5, 22, 12, 0, tzinfo=UTC),
                opponent=MATCH_ROW_OPPONENT,
                result="W",
                format_="Pauper",
                player_wins=2,
                player_losses=0,
            )
        ],
        total=1,
        page=1,
        per_page=20,
    )


def _opponent_stats() -> Any:
    """22 opponents: the named one first, so it lands on opponent page 1,
    and ``PAGE2_OPPONENT`` last, so it only appears on opponent page 2."""
    from web_service import analytics_client

    def _row(name: str) -> Any:
        return analytics_client.OpponentStatItem(
            opponent=name,
            matches=3,
            wins=2,
            losses=1,
            draws=0,
            win_rate=66.7,
        )

    names = [STATS_OPPONENT]
    names += [f"filler {i:02d}" for i in range(1, 21)]
    names.append(PAGE2_OPPONENT)
    return [_row(name) for name in names]


async def _render(app_client: httpx.AsyncClient, monkeypatch: Any, url: str) -> str:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_match_list(*_a: Any, **_kw: Any) -> Any:
        return _match_list()

    async def fake_by_opponent(*_a: Any, **_kw: Any) -> Any:
        return _opponent_stats()

    monkeypatch.setattr(analytics_client, "get_match_list", fake_match_list)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_by_opponent)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_player()
    try:
        r = await app_client.get(url)
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 200
    return r.text


def _sections(body: str) -> dict[str, str]:
    """Split the rendered page into its three opponent-link regions."""
    markers = [
        ("matches", ">Matches</h2>"),
        ("top_opponents", ">Top Opponents</h2>"),
        ("by_opponent", ">By opponent</h2>"),
    ]
    bounds: list[tuple[str, int]] = []
    for name, marker in markers:
        idx = body.find(marker)
        assert idx != -1, f"marker {marker!r} missing from rendered page"
        bounds.append((name, idx))

    out: dict[str, str] = {}
    for i, (name, start) in enumerate(bounds):
        end = bounds[i + 1][1] if i + 1 < len(bounds) else len(body)
        out[name] = body[start:end]
    return out


def _link_for(section: str, opponent: str, *, raw: bool = False) -> str:
    """The href of the anchor whose visible text is ``opponent``.

    Jinja autoescapes the attribute, so ``&`` separators arrive as ``&amp;``.
    The href is unescaped before it is returned unless ``raw`` is asked for.
    """
    hits = [
        href
        for href, text in re.findall(r'<a href="([^"]*)"[^>]*>([^<]*)</a>', section)
        if html.unescape(text).strip() == opponent
    ]
    assert len(hits) == 1, f"expected one link for {opponent!r}, got {hits}"
    return hits[0] if raw else html.unescape(hits[0])


def _all_opponent_links(body: str, *, raw: bool = False) -> dict[str, str]:
    sections = _sections(body)
    return {
        "matches": _link_for(sections["matches"], MATCH_ROW_OPPONENT, raw=raw),
        "top_opponents": _link_for(sections["top_opponents"], STATS_OPPONENT, raw=raw),
        "by_opponent": _link_for(sections["by_opponent"], STATS_OPPONENT, raw=raw),
    }


def _params(href: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(href).query)


@pytest.mark.asyncio
async def test_opponent_links_keep_the_active_filters(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(
        app_client,
        monkeypatch,
        "/matches?format=Pauper&date_from=2026-05-01&result=wins",
    )
    links = _all_opponent_links(body)
    assert set(links) == {"matches", "top_opponents", "by_opponent"}

    expected_opponent = {
        "matches": MATCH_ROW_OPPONENT,
        "top_opponents": STATS_OPPONENT,
        "by_opponent": STATS_OPPONENT,
    }
    for site, href in links.items():
        assert urlparse(href).path == "/matches", site
        params = _params(href)
        assert params["format"] == ["Pauper"], site
        assert params["date_from"] == ["2026-05-01"], site
        assert params["result"] == ["wins"], site
        assert params["opponent"] == [expected_opponent[site]], site


@pytest.mark.asyncio
async def test_opponent_links_carry_date_to_and_replace_the_old_opponent(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(
        app_client,
        monkeypatch,
        "/matches?format=Modern&date_from=2026-05-01&date_to=2026-06-01&opponent=zed",
    )
    for site, href in _all_opponent_links(body).items():
        params = _params(href)
        assert params["format"] == ["Modern"], site
        assert params["date_from"] == ["2026-05-01"], site
        assert params["date_to"] == ["2026-06-01"], site
        assert params["opponent"] != ["zed"], site


@pytest.mark.asyncio
async def test_opponent_links_reset_both_paginations(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Old page numbers are meaningless against a different result set."""
    body = await _render(
        app_client,
        monkeypatch,
        "/matches?format=Pauper&page=4&opp_page=2",
    )
    sections = _sections(body)
    links = {
        "matches": _link_for(sections["matches"], MATCH_ROW_OPPONENT),
        "top_opponents": _link_for(sections["top_opponents"], STATS_OPPONENT),
        # opp_page=2 is showing, so this row only exists on the second page.
        "by_opponent": _link_for(sections["by_opponent"], PAGE2_OPPONENT),
    }
    for site, href in links.items():
        params = _params(href)
        assert "page" not in params, site
        assert "opp_page" not in params, site
        assert params["format"] == ["Pauper"], site


@pytest.mark.asyncio
async def test_opponent_links_keep_a_non_default_page_size(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(app_client, monkeypatch, "/matches?per_page=50&format=Pauper")
    for site, href in _all_opponent_links(body).items():
        assert _params(href)["per_page"] == ["50"], site


@pytest.mark.asyncio
async def test_opponent_links_stay_clean_with_no_filters_active(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing to preserve means nothing extra in the URL, not per_page=20."""
    body = await _render(app_client, monkeypatch, "/matches")
    links = _all_opponent_links(body)

    assert links["matches"] == "/matches?opponent=bob+%26+jones"
    assert links["top_opponents"] == "/matches?opponent=carol+%26+dave"
    assert links["by_opponent"] == links["top_opponents"]

    for site, href in links.items():
        assert list(_params(href)) == ["opponent"], site


@pytest.mark.asyncio
async def test_opponent_names_are_encoded_once_and_escaped(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``&`` in a name must survive as one query value, not split the URL."""
    body = await _render(app_client, monkeypatch, "/matches?format=Pauper")
    raw_links = _all_opponent_links(body, raw=True)
    links = _all_opponent_links(body)
    expected = {
        "matches": MATCH_ROW_OPPONENT,
        "top_opponents": STATS_OPPONENT,
        "by_opponent": STATS_OPPONENT,
    }

    for site, raw in raw_links.items():
        # The literal "&" of the name is percent-encoded, so the only "&" left
        # in the attribute are the HTML-escaped parameter separators.
        assert "%26" in raw, site
        assert "&" not in raw.replace("&amp;", ""), site
        assert _params(links[site])["opponent"] == [expected[site]], site
        assert _params(links[site])["format"] == ["Pauper"], site
