"""Review-status chips must preserve the other active filters (#131).

Clicking a chip used to navigate to a bare ``?review_status=...`` URL, which
silently widened the result set an admin was triaging.
"""

from __future__ import annotations

import re
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


def _override_admin() -> Any:
    from web_service import deps as _deps

    fake_admin = _deps.BrowserUser(
        user_id=1,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-tok",
    )

    async def _dep() -> _deps.BrowserUser:
        return fake_admin

    return _dep


def _empty_match_list() -> Any:
    from web_service import analytics_client

    return analytics_client.AdminMatchListResponse(
        matches=[
            analytics_client.AdminMatchItem(
                match_id="00000000-0000-0000-0000-000000000001",
                user_id=42,
                user_email="alice@local",
                format_="Pauper",
                players=["alice", "bob"],
                match_result="2-0",
                winner="alice",
                game_count=2,
                played_at=datetime(2026, 5, 22, 12, 0, tzinfo=UTC),
                is_draw=False,
            )
        ],
        total=1,
        page=1,
        per_page=20,
    )


_CHIP_LABELS = ("All", "Pending review", "Rejected", "Normal")


def _chip_hrefs(body: str) -> dict[str, str]:
    """Map chip label -> href for the review-status chip row."""
    found: dict[str, str] = {}
    for href, label in re.findall(r'<a href="([^"]*)"[^>]*>([^<]+)</a>', body, re.DOTALL):
        label = label.strip()
        if label in _CHIP_LABELS and label not in found:
            found[label] = href
    return found


async def _render(app_client: httpx.AsyncClient, monkeypatch: Any, url: str) -> str:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_admin_matches(*_a: Any, **_kw: Any) -> Any:
        return _empty_match_list()

    monkeypatch.setattr(analytics_client, "admin_list_matches", fake_admin_matches)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get(url)
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 200
    return r.text


@pytest.mark.asyncio
async def test_chips_preserve_other_active_filters(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(
        app_client,
        monkeypatch,
        "/admin/matches?format=Pauper&opponent=alice&review_status=pending_review&page=3",
    )
    chips = _chip_hrefs(body)
    assert set(chips) == set(_CHIP_LABELS)

    for label, href in chips.items():
        assert "format=Pauper" in href, label
        assert "opponent=alice" in href, label
        assert "page=" not in href, label

    assert "review_status" not in chips["All"]
    assert "review_status=pending_review" in chips["Pending review"]
    assert "review_status=rejected" in chips["Rejected"]
    assert "review_status=normal" in chips["Normal"]


@pytest.mark.asyncio
async def test_chips_are_clean_urls_when_no_filters_active(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(app_client, monkeypatch, "/admin/matches")
    chips = _chip_hrefs(body)

    assert chips["All"] == "/admin/matches"
    assert chips["Pending review"] == "/admin/matches?review_status=pending_review"
    assert chips["Rejected"] == "/admin/matches?review_status=rejected"
    assert chips["Normal"] == "/admin/matches?review_status=normal"


@pytest.mark.asyncio
async def test_chips_keep_a_non_default_page_size(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(app_client, monkeypatch, "/admin/matches?per_page=50&format=Pauper")
    for label, href in _chip_hrefs(body).items():
        assert "per_page=50" in href, label


@pytest.mark.asyncio
async def test_chips_carry_date_and_result_filters(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = await _render(
        app_client,
        monkeypatch,
        "/admin/matches?result=win&date_from=2026-01-01&date_to=2026-02-01",
    )
    for label, href in _chip_hrefs(body).items():
        assert "result=win" in href, label
        assert "date_from=2026-01-01" in href, label
        assert "date_to=2026-02-01" in href, label


@pytest.mark.asyncio
async def test_chips_still_render_on_the_analytics_error_page(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 503 branch renders the same template, so it needs the same
    chip context keys."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("down")

    monkeypatch.setattr(analytics_client, "admin_list_matches", boom)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/matches?format=Pauper&per_page=50")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503
    chips = _chip_hrefs(r.text)
    assert set(chips) == set(_CHIP_LABELS)
    for label, href in chips.items():
        assert "format=Pauper" in href, label
        assert "per_page=50" in href, label
