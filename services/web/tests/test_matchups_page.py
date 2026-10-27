"""Matchups page (issue #129): route wiring, rendering and client query string."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio

HERO = "11111111-1111-1111-1111-111111111111"
OPP = "22222222-2222-2222-2222-222222222222"


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


def _override_user(role: str = "user") -> Any:
    from web_service import deps as _deps

    player = _deps.BrowserUser(
        user_id=42,
        email="alice@local",
        role=role,
        must_change_password=False,
        scope=None,
        token="player-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return player

    return _dep


def _cell(
    *,
    hero: str = "Burn",
    opp: str = "Tron",
    matches: int = 8,
    wins: int = 6,
    losses: int = 2,
    low_sample: bool = False,
    preboard: Any = None,
    postboard: Any = None,
) -> Any:
    from web_service import analytics_client

    decided = wins + losses
    return analytics_client.MatchupCellItem(
        hero_archetype_id=HERO,
        hero_archetype=hero,
        opponent_archetype_id=OPP,
        opponent_archetype=opp,
        matches=matches,
        wins=wins,
        losses=losses,
        draws=matches - decided,
        decided=decided,
        win_rate=(wins / decided) * 100.0 if decided else 0.0,
        win_rate_low=40.0,
        win_rate_high=90.0,
        low_sample=low_sample,
        preboard=preboard or analytics_client.BoardSplitItem(),
        postboard=postboard or analytics_client.BoardSplitItem(),
    )


def _archetype(arch_id: str, name: str, fmt: str = "Modern") -> Any:
    from web_service import analytics_client

    return analytics_client.ArchetypeItem(
        id=arch_id,
        name=name,
        format=fmt,
        defining_cards=[],
        sample_decklists=None,
        created_at=None,
        updated_at=None,
    )


async def _get(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    *,
    matrix: Any = None,
    role: str = "user",
    raises: Exception | None = None,
    archetypes: list[Any] | None = None,
) -> tuple[httpx.Response, dict[str, Any]]:
    """GET ``url`` with analytics faked; return the response and the client kwargs."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    seen: dict[str, Any] = {}

    async def fake_matchups(*_a: Any, **kw: Any) -> Any:
        seen["matchups"] = kw
        if raises:
            raise raises
        return matrix if matrix is not None else analytics_client.MatchupMatrix()

    async def fake_archetypes(*_a: Any, **_kw: Any) -> Any:
        items = archetypes or [_archetype(HERO, "Burn"), _archetype(OPP, "Tron")]
        return items, len(items)

    monkeypatch.setattr(analytics_client, "get_matchups", fake_matchups)
    monkeypatch.setattr(analytics_client, "admin_list_archetypes", fake_archetypes)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user(role)
    try:
        r = await app_client.get(url)
    finally:
        _main.app.dependency_overrides.clear()
    return r, seen


@pytest.mark.asyncio
async def test_filters_reach_the_client(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, seen = await _get(
        app_client,
        monkeypatch,
        f"/matchups?format=Modern&date_from=2026-05-01&date_to=2026-05-31"
        f"&hero_archetype_id={HERO}&opponent_archetype_id={OPP}",
    )

    assert r.status_code == 200
    assert seen["matchups"] == {
        "format_filter": "Modern",
        "date_from": "2026-05-01",
        "date_to": "2026-05-31",
        "hero_archetype_id": HERO,
        "opponent_archetype_id": OPP,
    }


@pytest.mark.asyncio
async def test_archetype_filters_from_another_format_are_cleared(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing Format and resubmitting still posts the old format's archetype IDs.

    The selects only list the new format's archetypes, so the stale IDs would
    show as "All" while silently constraining the results.
    """
    r, seen = await _get(
        app_client,
        monkeypatch,
        f"/matchups?format=Pauper&hero_archetype_id={HERO}&opponent_archetype_id={OPP}",
    )

    assert r.status_code == 200
    assert seen["matchups"]["format_filter"] == "Pauper"
    assert seen["matchups"]["hero_archetype_id"] is None
    assert seen["matchups"]["opponent_archetype_id"] is None
    assert f'value="{HERO}" selected' not in r.text
    assert f'value="{OPP}" selected' not in r.text


@pytest.mark.asyncio
async def test_only_the_incompatible_archetype_filter_is_cleared(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, seen = await _get(
        app_client,
        monkeypatch,
        f"/matchups?format=Pauper&hero_archetype_id={HERO}&opponent_archetype_id={OPP}",
        archetypes=[_archetype(HERO, "Burn", "Modern"), _archetype(OPP, "Elves", "Pauper")],
    )

    assert r.status_code == 200
    assert seen["matchups"]["hero_archetype_id"] is None
    assert seen["matchups"]["opponent_archetype_id"] == OPP
    assert f'<option value="{OPP}" selected>Elves</option>' in r.text


@pytest.mark.asyncio
async def test_archetype_filters_are_kept_when_no_format_is_chosen(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _r, seen = await _get(app_client, monkeypatch, f"/matchups?hero_archetype_id={HERO}")

    assert seen["matchups"]["hero_archetype_id"] == HERO


@pytest.mark.asyncio
async def test_unfiltered_page_sends_no_filters(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The form submits "" for "All"; a hand-edited non-UUID must not reach analytics.
    r, seen = await _get(
        app_client, monkeypatch, "/matchups?format=&hero_archetype_id=&opponent_archetype_id=junk"
    )

    assert r.status_code == 200
    assert seen["matchups"] == {
        "format_filter": None,
        "date_from": None,
        "date_to": None,
        "hero_archetype_id": None,
        "opponent_archetype_id": None,
    }


@pytest.mark.asyncio
async def test_table_renders_counts_win_rate_and_drilldown_links(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    matrix = analytics_client.MatchupMatrix(cells=[_cell()])
    r, _seen = await _get(
        app_client, monkeypatch, "/matchups?format=Modern&date_from=2026-05-01", matrix=matrix
    )

    body = r.text
    assert "Burn" in body and "Tron" in body
    assert "75.0%" in body  # 6 / (6 + 2)
    assert ">6</a>-<a" in body and ">2</a>-0" in body  # W-L-D, wins and losses linked
    assert "40&ndash;90%" in body or "40–90%" in body
    assert "Low sample" not in body
    # Drill-down keeps the format/date filters the user already set.
    assert f"/matchups?format=Modern&amp;date_from=2026-05-01&amp;hero_archetype_id={HERO}" in body


@pytest.mark.asyncio
async def test_low_sample_cell_is_visibly_marked(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    matrix = analytics_client.MatchupMatrix(
        cells=[_cell(matches=2, wins=2, losses=0, low_sample=True)]
    )
    r, _seen = await _get(app_client, monkeypatch, "/matchups", matrix=matrix)

    assert "Low sample" in r.text
    assert "Fewer than 5 decided matches" in r.text


@pytest.mark.asyncio
async def test_unclassified_matches_are_disclosed(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    matrix = analytics_client.MatchupMatrix(cells=[_cell()], unclassified_matches=3)
    r, _seen = await _get(app_client, monkeypatch, "/matchups", matrix=matrix)

    assert "3 matches in this view could not be classified" in r.text


@pytest.mark.asyncio
async def test_empty_matrix_says_so(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, _seen = await _get(app_client, monkeypatch, "/matchups")

    assert r.status_code == 200
    assert "No classified matches match these filters." in r.text


@pytest.mark.asyncio
async def test_archetype_selects_list_the_catalog_and_keep_the_selection(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, _seen = await _get(app_client, monkeypatch, f"/matchups?hero_archetype_id={HERO}")

    assert f'<option value="{HERO}" selected>Burn (Modern)</option>' in r.text
    assert f'<option value="{OPP}" >Tron (Modern)</option>' in r.text


@pytest.mark.asyncio
async def test_invalid_date_range_skips_analytics_and_shows_error(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, seen = await _get(
        app_client, monkeypatch, "/matchups?date_from=2026-06-01&date_to=2026-05-01"
    )

    assert r.status_code == 200
    assert "matchups" not in seen
    assert "date_from must not be later than date_to." in r.text


@pytest.mark.asyncio
async def test_analytics_failure_renders_error_banner(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    r, _seen = await _get(
        app_client, monkeypatch, "/matchups", raises=analytics_client.AnalyticsClientError("boom")
    )

    assert r.status_code == 200
    assert "Matchups unavailable" in r.text


@pytest.mark.asyncio
async def test_expired_session_redirects_to_login(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    r, _seen = await _get(
        app_client, monkeypatch, "/matchups", raises=analytics_client.AnalyticsForbidden("401")
    )

    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_admin_is_redirected_to_admin_landing(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, seen = await _get(app_client, monkeypatch, "/matchups", role="admin")

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"
    assert "matchups" not in seen


@pytest.mark.asyncio
async def test_nav_links_to_matchups(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, _seen = await _get(app_client, monkeypatch, "/matchups")

    assert 'href="/matchups"' in r.text


@pytest.mark.asyncio
async def test_client_puts_filters_on_the_query_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client

    seen: dict[str, Any] = {}

    class _Resp:
        @staticmethod
        def json() -> dict[str, Any]:
            return {
                "min_sample": 5,
                "unclassified_matches": 2,
                "cells": [
                    {
                        "hero_archetype_id": HERO,
                        "hero_archetype": "Burn",
                        "opponent_archetype_id": OPP,
                        "opponent_archetype": "Tron",
                        "matches": 3,
                        "wins": 2,
                        "losses": 1,
                        "draws": 0,
                        "decided": 3,
                        "win_rate": 66.7,
                        "win_rate_low": 20.8,
                        "win_rate_high": 93.9,
                        "low_sample": True,
                    }
                ],
            }

    async def fake_request(_method: str, url: str, **kw: Any) -> Any:
        seen["url"] = url
        seen["params"] = kw.get("params")
        return _Resp()

    monkeypatch.setattr(analytics_client, "request", fake_request)

    matrix = await analytics_client.get_matchups(
        "http://analytics",
        "tok",
        format_filter="Modern",
        date_from="2026-05-01",
        date_to="2026-05-31",
        hero_archetype_id=HERO,
        opponent_archetype_id=OPP,
    )

    assert seen["url"] == "http://analytics/analytics/stats/matchups"
    assert seen["params"] == {
        "format": "Modern",
        "date_from": "2026-05-01",
        "date_to": "2026-05-31",
        "hero_archetype_id": HERO,
        "opponent_archetype_id": OPP,
    }
    assert matrix.unclassified_matches == 2
    assert matrix.cells[0].low_sample is True
    assert matrix.cells[0].win_rate_high == 93.9


@pytest.mark.asyncio
async def test_client_drops_all_sentinel_and_blanks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client

    seen: dict[str, Any] = {}

    class _Resp:
        @staticmethod
        def json() -> dict[str, Any]:
            return {}

    async def fake_request(_method: str, _url: str, **kw: Any) -> Any:
        seen["params"] = kw.get("params")
        return _Resp()

    monkeypatch.setattr(analytics_client, "request", fake_request)

    matrix = await analytics_client.get_matchups("http://analytics", "tok", format_filter="all")

    assert seen["params"] == {}
    assert matrix.cells == []


# ---------------------------------------------------------------------------
# Pre-board / post-board split and drill-down links
# ---------------------------------------------------------------------------


def _split(games: int, wins: int, *, low_sample: bool = False) -> Any:
    from web_service import analytics_client

    return analytics_client.BoardSplitItem(
        games=games,
        wins=wins,
        losses=games - wins,
        win_rate=(wins / games) * 100.0 if games else 0.0,
        win_rate_low=30.0,
        win_rate_high=80.0,
        low_sample=low_sample,
    )


@pytest.mark.asyncio
async def test_split_columns_show_each_side_with_its_own_low_sample_mark(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    cell = _cell(preboard=_split(10, 7), postboard=_split(3, 1, low_sample=True))
    r, _seen = await _get(
        app_client, monkeypatch, "/matchups", matrix=analytics_client.MatchupMatrix(cells=[cell])
    )

    body = r.text
    assert "Pre-board" in body and "Post-board" in body
    assert "70.0%" in body  # G1: 7 / 10
    assert "33.3%" in body  # G2+: 1 / 3
    # The 3-game post-board side is marked; the 10-game pre-board side is not.
    # (the cell itself is not low sample, so this badge can only be the split's).
    assert body.count("Low sample") == 1
    assert "Fewer than 5 games" in body


@pytest.mark.asyncio
async def test_empty_postboard_reads_as_no_games_not_zero_percent(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    cell = _cell(preboard=_split(2, 1, low_sample=True))
    r, _seen = await _get(
        app_client, monkeypatch, "/matchups", matrix=analytics_client.MatchupMatrix(cells=[cell])
    )

    assert "no games" in r.text
    assert not re.search(r"(?<![\d.])0\.0%", r.text)


@pytest.mark.asyncio
async def test_cell_links_to_supporting_matches_with_format_and_dates(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    matrix = analytics_client.MatchupMatrix(cells=[_cell()])
    r, _seen = await _get(
        app_client,
        monkeypatch,
        "/matchups?format=Modern&date_from=2026-05-01&date_to=2026-05-31",
        matrix=matrix,
    )

    base = (
        "/matches?format=Modern&amp;date_from=2026-05-01&amp;date_to=2026-05-31"
        f"&amp;hero_archetype_id={HERO}&amp;opponent_archetype_id={OPP}"
    )
    assert f'href="{base}"' in r.text  # the match count
    assert f'href="{base}&amp;result=wins"' in r.text
    assert f'href="{base}&amp;result=losses"' in r.text


@pytest.mark.asyncio
async def test_cell_link_replaces_the_pages_archetype_filters_with_the_cells(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from web_service import analytics_client

    other = "33333333-3333-3333-3333-333333333333"
    r, _seen = await _get(
        app_client,
        monkeypatch,
        f"/matchups?hero_archetype_id={HERO}",
        matrix=analytics_client.MatchupMatrix(cells=[_cell()]),
        archetypes=[_archetype(HERO, "Burn"), _archetype(OPP, "Tron"), _archetype(other, "Other")],
    )

    assert f'href="/matches?hero_archetype_id={HERO}&amp;opponent_archetype_id={OPP}"' in r.text


@pytest.mark.asyncio
async def test_client_parses_the_split_and_tolerates_its_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client

    base = {
        "hero_archetype_id": HERO,
        "hero_archetype": "Burn",
        "opponent_archetype_id": OPP,
        "opponent_archetype": "Tron",
        "matches": 1,
    }
    payload = {
        "cells": [
            {
                **base,
                "preboard": {
                    "games": 4,
                    "wins": 3,
                    "losses": 1,
                    "win_rate": 75.0,
                    "low_sample": True,
                },
                "postboard": {"games": 0},
            },
            base,  # an older analytics build with no split at all
        ]
    }

    class _Resp:
        @staticmethod
        def json() -> dict[str, Any]:
            return payload

    async def fake_request(*_a: Any, **_kw: Any) -> Any:
        return _Resp()

    monkeypatch.setattr(analytics_client, "request", fake_request)

    with_split, without = (await analytics_client.get_matchups("http://a", "t")).cells

    assert (with_split.preboard.games, with_split.preboard.wins, with_split.preboard.win_rate) == (
        4,
        3,
        75.0,
    )
    assert with_split.postboard.games == 0 and with_split.postboard.low_sample is True
    assert without.preboard.games == 0 and without.postboard.low_sample is True


# ---------------------------------------------------------------------------
# Match History: the landing end of the drill-down
# ---------------------------------------------------------------------------


async def _get_matches(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, url: str
) -> tuple[httpx.Response, dict[str, Any]]:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    seen: dict[str, Any] = {}

    async def fake_match_list(*_a: Any, **kw: Any) -> Any:
        seen["match_list"] = kw
        return analytics_client.MatchListResponse(matches=[], total=0, page=1, per_page=20)

    async def fake_by_opponent(*_a: Any, **kw: Any) -> Any:
        seen["by_opponent"] = kw
        return []

    monkeypatch.setattr(analytics_client, "get_match_list", fake_match_list)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_by_opponent)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(url)
    finally:
        _main.app.dependency_overrides.clear()
    return r, seen


@pytest.mark.asyncio
async def test_match_history_forwards_archetype_filters_to_both_calls(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, seen = await _get_matches(
        app_client,
        monkeypatch,
        f"/matches?hero_archetype_id={HERO}&opponent_archetype_id={OPP}&format=Modern",
    )

    assert r.status_code == 200
    for call in ("match_list", "by_opponent"):
        assert seen[call]["hero_archetype_id"] == HERO, call
        assert seen[call]["opponent_archetype_id"] == OPP, call
    # The filter form keeps them, and the page says a matchup filter is on.
    assert f'name="hero_archetype_id" value="{HERO}"' in r.text
    assert f'name="opponent_archetype_id" value="{OPP}"' in r.text
    assert "Clear matchup filter" in r.text
    assert 'href="/matchups?format=Modern"' in r.text


@pytest.mark.asyncio
async def test_match_history_drops_non_uuid_archetype_filters(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, seen = await _get_matches(
        app_client, monkeypatch, "/matches?hero_archetype_id=nope&opponent_archetype_id="
    )

    assert r.status_code == 200
    assert seen["match_list"]["hero_archetype_id"] is None
    assert seen["match_list"]["opponent_archetype_id"] is None
    assert "Clear matchup filter" not in r.text


@pytest.mark.asyncio
async def test_match_history_without_archetype_filters_shows_no_matchup_chip(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    r, _seen = await _get_matches(app_client, monkeypatch, "/matches")

    assert "Clear matchup filter" not in r.text
    assert 'name="hero_archetype_id"' not in r.text


@pytest.mark.asyncio
async def test_client_sends_archetype_filters_for_match_list_and_by_opponent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client

    seen: list[dict[str, Any]] = []

    class _Resp:
        @staticmethod
        def json() -> Any:
            return {}

    async def fake_request(_method: str, _url: str, **kw: Any) -> Any:
        seen.append(kw["params"])
        return _Resp()

    monkeypatch.setattr(analytics_client, "request", fake_request)

    await analytics_client.get_match_list(
        "http://a", "t", hero_archetype_id=HERO, opponent_archetype_id=OPP
    )
    await analytics_client.get_stats_by_opponent(
        "http://a", "t", hero_archetype_id=HERO, opponent_archetype_id=OPP
    )

    for params in seen:
        assert params["hero_archetype_id"] == HERO
        assert params["opponent_archetype_id"] == OPP
