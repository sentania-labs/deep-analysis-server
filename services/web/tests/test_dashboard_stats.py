"""Tests for the user-facing /dashboard stats view.

Bypasses browser auth via FastAPI dependency overrides and patches
the analytics client so we can exercise template rendering and the
error-banner branch without a live analytics service.
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


def _sample_summary(*, total: int = 0) -> Any:
    from web_service import analytics_client

    if total == 0:
        return analytics_client.StatsSummary(
            total_matches=0,
            wins=0,
            losses=0,
            draws=0,
            win_rate=0.0,
            recent_matches=[],
        )
    recent = [
        analytics_client.RecentMatchItem(
            match_id="abc-123",
            played_at=datetime(2026, 5, 9, 12, 0, tzinfo=UTC),
            opponent="bob",
            result="W",
            format_="Modern",
            player_wins=2,
            player_losses=1,
        ),
    ]
    return analytics_client.StatsSummary(
        total_matches=total,
        wins=4,
        losses=2,
        draws=1,
        win_rate=66.7,
        recent_matches=recent,
    )


def _sample_format_stats() -> list[Any]:
    from web_service import analytics_client

    return [
        analytics_client.FormatStatItem(
            format_="Modern",
            matches=5,
            wins=3,
            losses=2,
            draws=0,
            win_rate=60.0,
        ),
    ]


def _sample_opponent_stats() -> list[Any]:
    from web_service import analytics_client

    return [
        analytics_client.OpponentStatItem(
            opponent="bob",
            matches=3,
            wins=2,
            losses=1,
            draws=0,
            win_rate=66.7,
        ),
    ]


# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_renders_with_stats(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_summary(_url: str, _token: str) -> Any:
        return _sample_summary(total=7)

    async def fake_format(_url: str, _token: str) -> Any:
        return _sample_format_stats()

    async def fake_opponent(_url: str, _token: str) -> Any:
        return _sample_opponent_stats()

    async def fake_match_list(_url: str, _token: str, **_kw: Any) -> Any:
        return analytics_client.MatchListResponse(
            matches=[
                analytics_client.MatchListItem(
                    match_id="abc-123",
                    played_at=datetime(2026, 5, 9, 12, 0, tzinfo=UTC),
                    opponent="bob",
                    result="W",
                    format_="Modern",
                    player_wins=2,
                    player_losses=1,
                ),
            ],
            total=1,
            page=1,
            per_page=20,
        )

    async def fake_play_draw(_url: str, _token: str, **_kw: Any) -> Any:
        return analytics_client.PlayDrawStats(
            on_play_matches=10,
            on_play_wins=6,
            on_play_win_rate=60.0,
            on_draw_matches=8,
            on_draw_wins=3,
            on_draw_win_rate=37.5,
        )

    async def fake_preboard(_url: str, _token: str, **_kw: Any) -> Any:
        return analytics_client.PreboardPostboardStats(
            game1_matches=10,
            game1_wins=5,
            game1_win_rate=50.0,
            games23_matches=8,
            games23_wins=4,
            games23_win_rate=50.0,
        )

    async def fake_mulligan(_url: str, _token: str, **_kw: Any) -> Any:
        return analytics_client.MulliganStats(
            buckets=[
                analytics_client.MulliganBucket(hand_size=7, games=12, wins=8, win_rate=66.7),
                analytics_client.MulliganBucket(hand_size=6, games=4, wins=2, win_rate=50.0),
            ]
        )

    async def fake_card_stats(_url: str, _token: str, **_kw: Any) -> Any:
        return analytics_client.CardStatsResponse(
            cards=[
                analytics_client.CardStatItem(
                    card_name="Lightning Bolt",
                    games=10,
                    wins=7,
                    win_rate=70.0,
                    avg_cast_turn=2.3,
                ),
            ],
            total=1,
            page=1,
            per_page=20,
        )

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_format)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_opponent)
    monkeypatch.setattr(analytics_client, "get_match_list", fake_match_list)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", fake_play_draw)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", fake_preboard)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", fake_mulligan)
    monkeypatch.setattr(analytics_client, "get_card_stats", fake_card_stats)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    text = r.text
    assert "Total matches" in text
    assert "Win rate" in text
    assert "66.7%" in text
    # Format breakdown table is on the overview
    assert "By format" in text
    assert "Modern" in text
    # No error banner
    assert "Stats unavailable" not in text
    # Stats panels are rendered inline on initial load (v0.9.4 UX rework)
    assert "Play/Draw Split" in text
    assert "On Play" in text
    assert "Card Performance" in text
    assert "Lightning Bolt" in text


@pytest.mark.asyncio
async def test_dashboard_empty_state_no_matches(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_summary(_url: str, _token: str) -> Any:
        return _sample_summary(total=0)

    async def fake_format(_url: str, _token: str) -> Any:
        return []

    async def fake_opponent(_url: str, _token: str) -> Any:
        return []

    async def fake_match_list(_url: str, _token: str, **_kw: Any) -> Any:
        return analytics_client.MatchListResponse(matches=[], total=0, page=1, per_page=20)

    async def fake_none(*_a: Any, **_kw: Any) -> None:
        raise analytics_client.AnalyticsClientError("no data")

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_format)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_opponent)
    monkeypatch.setattr(analytics_client, "get_match_list", fake_match_list)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", fake_none)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", fake_none)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", fake_none)
    monkeypatch.setattr(analytics_client, "get_card_stats", fake_none)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "No matches yet" in r.text
    # No breakdown sections
    assert "By format" not in r.text
    assert "By opponent" not in r.text
    # v0.9.0 widgets also not shown when analytics unavailable
    assert "Play/Draw Split" not in r.text


@pytest.mark.asyncio
async def test_dashboard_renders_error_banner_on_analytics_failure(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "get_stats_summary", boom)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", boom)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", boom)
    monkeypatch.setattr(analytics_client, "get_match_list", boom)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", boom)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", boom)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", boom)
    monkeypatch.setattr(analytics_client, "get_card_stats", boom)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "Stats unavailable" in r.text


@pytest.mark.asyncio
async def test_dashboard_unauth_redirects_to_login(
    app_client: httpx.AsyncClient,
) -> None:
    r = await app_client.get("/dashboard")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_dashboard_admin_redirects_to_admin_users(
    app_client: httpx.AsyncClient,
) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    fake_admin = _deps.BrowserUser(
        user_id=1,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-tok",
    )

    async def dep() -> _deps.BrowserUser:
        return fake_admin

    _main.app.dependency_overrides[_deps.get_current_browser_user] = dep
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 302
    assert r.headers["location"] == "/admin/users"
