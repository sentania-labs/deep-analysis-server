"""Tests for date-range validation on dashboard / matches routes and HTMX partials.

These exercises cover the acceptance criteria for FDY-0456 / issue 128:

- AC1: inverted date ranges (date_from > date_to) render an inline error and do NOT
  reach analytics.
- AC2: malformed dates render an inline error (no 422 / 500).
- AC3: a valid range behaves as before (normal stats rendering).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Unit tests for validate_date_range helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_date_range_valid() -> None:
    from web_service.main import validate_date_range

    ok, err = validate_date_range("2026-09-01", "2026-09-10")
    assert ok is True
    assert err is None

    ok, err = validate_date_range("2026-09-10", "2026-09-10")
    assert ok is True
    assert err is None

    # Empty strings are always valid (no filter).
    ok, err = validate_date_range("", "")
    assert ok is True
    assert err is None

    ok, err = validate_date_range("2026-09-01", "")
    assert ok is True
    assert err is None


@pytest.mark.asyncio
async def test_validate_date_range_inverted() -> None:
    from web_service.main import validate_date_range

    ok, err = validate_date_range("2026-09-10", "2026-09-01")
    assert ok is False
    assert "date_from must not be later" in err


@pytest.mark.asyncio
async def test_validate_date_range_malformed() -> None:
    from web_service.main import validate_date_range

    ok, err = validate_date_range("notadate", "2026-09-10")
    assert ok is False
    assert "Invalid 'From' date" in err

    ok, err = validate_date_range("2026-09-01", "notadate")
    assert ok is False
    assert "Invalid 'To' date" in err


# ---------------------------------------------------------------------------
# AC1: inverted date range on /dashboard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_inverted_dates_renders_error_no_analytics_call(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC1: date_from > date_to renders inline error and makes no analytics call."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    call_count: dict[str, int] = {}

    async def fake_summary(*_a: Any, **_kw: Any) -> Any:
        call_count["summary"] = call_count.get("summary", 0) + 1
        raise AssertionError("analytics should NOT be called for inverted dates")

    async def fake_any(*_a: Any, **_kw: Any) -> Any:
        call_count["any"] = call_count.get("any", 0) + 1
        raise AssertionError("analytics should NOT be called")

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_any)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_card_stats", fake_any)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/dashboard",
            params={
                "date_from": "2026-09-10",
                "date_to": "2026-09-01",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "date_from must not be later" in r.text
    # Entered values are preserved in the form.
    assert "2026-09-10" in r.text
    assert "2026-09-01" in r.text
    # No analytics call was made.
    assert call_count.get("summary", 0) == 0
    assert call_count.get("any", 0) == 0


# ---------------------------------------------------------------------------
# AC1: inverted date range on /matches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_match_history_inverted_dates_renders_error_no_analytics_call(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC1: inverted dates on /matches renders error, no analytics call."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    call_count: dict[str, int] = {}

    async def fake_any(*_a: Any, **_kw: Any) -> Any:
        call_count["called"] = call_count.get("called", 0) + 1
        raise AssertionError("analytics should NOT be called")

    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_any)
    monkeypatch.setattr(analytics_client, "get_match_list", fake_any)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/matches",
            params={
                "date_from": "2026-09-10",
                "date_to": "2026-09-01",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "date_from must not be later" in r.text
    assert call_count.get("called", 0) == 0


# ---------------------------------------------------------------------------
# AC1: inverted date range on HTMX partials (no 422)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_htmx_partial_inverted_dates_no_422(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC1: HTMX partials with inverted dates return 200, not 422."""
    from web_service import deps as _deps
    from web_service import main as _main

    monkeypatch.setattr(
        "web_service.analytics_client.get_play_draw_stats",
        lambda *_a, **_kw: (_ for _ in ()).throw(Exception("should not be called")),
    )

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/dashboard/partials/play-draw",
            params={
                "date_from": "2026-09-10",
                "date_to": "2026-09-01",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "date_from must not be later" in r.text


@pytest.mark.asyncio
async def test_htmx_card_performance_partial_inverted_dates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC1: card-performance HTMX partial with inverted dates returns 200 with error."""
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/dashboard/partials/card-performance",
            params={
                "date_from": "2026-09-10",
                "date_to": "2026-09-01",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "date_from must not be later" in r.text


# ---------------------------------------------------------------------------
# AC2: malformed date on /dashboard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_malformed_date_renders_error_not_422(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC2: date_from=notadate renders an inline error, not a 422 or 500."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    call_count: dict[str, int] = {}

    async def fake_summary(*_a: Any, **_kw: Any) -> Any:
        call_count["called"] = call_count.get("called", 0) + 1
        raise AssertionError("analytics should NOT be called")

    async def fake_any(*_a: Any, **_kw: Any) -> Any:
        call_count["any"] = call_count.get("any", 0) + 1
        raise AssertionError("analytics should NOT be called")

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_any)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_card_stats", fake_any)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard", params={"date_from": "notadate"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # The error text is HTML-escaped by Jinja2, so check for the unescaped
    # substring or its HTML-entity form.
    body_lower = r.text.lower()
    assert "invalid" in body_lower and "from" in body_lower and "date" in body_lower
    assert call_count.get("called", 0) == 0


@pytest.mark.asyncio
async def test_dashboard_malformed_date_to(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC2: date_to=notadate renders error, no analytics call."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    call_count: dict[str, int] = {}

    async def fake_summary(*_a: Any, **_kw: Any) -> Any:
        call_count["called"] = call_count.get("called", 0) + 1
        raise AssertionError("analytics should NOT be called")

    async def fake_any(*_a: Any, **_kw: Any) -> Any:
        call_count["any"] = call_count.get("any", 0) + 1
        raise AssertionError("analytics should NOT be called")

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_any)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_card_stats", fake_any)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard", params={"date_to": "notadate"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body_lower = r.text.lower()
    assert "invalid" in body_lower and "to" in body_lower and "date" in body_lower


# ---------------------------------------------------------------------------
# AC3: valid range behaves as before
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_valid_date_range_renders_stats(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC3: a valid date range works normally, analytics is called."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    calls: list[str] = []

    async def fake_summary(*_a: Any, **_kw: Any) -> Any:
        calls.append("summary")
        return _sample_summary(total=3)

    async def fake_format(*_a: Any, **_kw: Any) -> Any:
        calls.append("format")
        return []

    async def fake_opponent(*_a: Any, **_kw: Any) -> Any:
        calls.append("opponent")
        return []

    async def fake_match_list(*_a: Any, **_kw: Any) -> Any:
        calls.append("match_list")
        return analytics_client.MatchListResponse(matches=[], total=0, page=1, per_page=20)

    async def fake_none(*_a: Any, **_kw: Any) -> Any:
        calls.append("other")
        raise analytics_client.AnalyticsClientError("stub")

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
        r = await app_client.get(
            "/dashboard",
            params={
                "date_from": "2026-09-01",
                "date_to": "2026-09-30",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # No date error rendered.
    assert "date_from must not be later" not in r.text
    # No invalid-date error rendered (Jinja2 may HTML-escape quotes).
    body_lower = r.text.lower()
    assert "invalid &#39;from" not in body_lower
    assert "invalid &#39;to" not in body_lower
    # Analytics was called (summary called because dashboard is first).
    assert "summary" in calls
    assert "format" in calls


@pytest.mark.asyncio
async def test_match_history_valid_date_range(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC3: /matches with valid dates works normally."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    calls: list[str] = []

    async def fake_opponent(*_a: Any, **_kw: Any) -> Any:
        calls.append("opponent")
        return []

    async def fake_match_list(*_a: Any, **_kw: Any) -> Any:
        calls.append("match_list")
        return analytics_client.MatchListResponse(matches=[], total=0, page=1, per_page=20)

    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_opponent)
    monkeypatch.setattr(analytics_client, "get_match_list", fake_match_list)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(
            "/matches",
            params={
                "date_from": "2026-09-01",
                "date_to": "2026-09-30",
            },
        )
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body_lower = r.text.lower()
    assert "invalid &#39;from" not in body_lower
    assert "invalid &#39;to" not in body_lower
    assert "opponent" in calls
    assert "match_list" in calls


# ---------------------------------------------------------------------------
# AC3: no date filter (both empty) behaves as before
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_no_date_filter_works(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC3: without date parameters the dashboard works as before."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_summary(*_a: Any, **_kw: Any) -> Any:
        return _sample_summary(total=5)

    async def fake_list(*_a: Any, **_kw: Any) -> Any:
        return []

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_list)
    monkeypatch.setattr(analytics_client, "get_stats_by_opponent", fake_list)
    monkeypatch.setattr(
        analytics_client,
        "get_match_list",
        lambda *a, **k: analytics_client.MatchListResponse(
            matches=[], total=0, page=1, per_page=20
        ),
    )

    async def _throw(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("stub")

    monkeypatch.setattr(analytics_client, "get_play_draw_stats", _throw)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", _throw)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", _throw)
    monkeypatch.setattr(analytics_client, "get_card_stats", _throw)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    # No date-error banners rendered.
    assert "date_from must not be later" not in r.text
    body_lower = r.text.lower()
    assert "invalid &#39;from" not in body_lower
    assert "invalid &#39;to" not in body_lower


# ---------------------------------------------------------------------------
# Edge: only date_from or only date_to provided
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_single_date_filter_works(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC3: one-sided date filter (no inversion possible) works normally."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_summary(*_a: Any, **_kw: Any) -> Any:
        return _sample_summary(total=2)

    async def fake_any(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("stub")

    monkeypatch.setattr(analytics_client, "get_stats_summary", fake_summary)
    monkeypatch.setattr(analytics_client, "get_stats_by_format", fake_any)
    monkeypatch.setattr(analytics_client, "get_play_draw_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_preboard_postboard_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_mulligan_stats", fake_any)
    monkeypatch.setattr(analytics_client, "get_card_stats", fake_any)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/dashboard", params={"date_from": "2026-01-01"})
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "date_from must not be later" not in r.text
    body_lower = r.text.lower()
    assert "invalid &#39;from" not in body_lower
    assert "invalid &#39;to" not in body_lower
