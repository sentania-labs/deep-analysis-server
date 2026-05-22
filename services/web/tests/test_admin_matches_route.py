"""Admin matches list template rendering tests (#71).

The /admin/matches list previously rendered any null-winner match
with ``game_count > 0`` as "Draw". After issue #71 the template
keys off ``is_draw`` (set server-side from the per-match game-winner
counts) instead, so partial-parse husks render "—" and only true
draws render "Draw".
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


def _make_admin_matches() -> Any:
    from web_service import analytics_client

    return analytics_client.AdminMatchListResponse(
        matches=[
            # 1. Decided match — winner set, should NOT show "Draw".
            analytics_client.AdminMatchItem(
                match_id="00000000-0000-0000-0000-000000000001",
                user_id=42,
                user_email="alice@local",
                format_="Modern",
                players=["alice", "bob"],
                match_result="2-1",
                winner="alice",
                game_count=3,
                played_at=datetime(2026, 5, 22, 12, 0, tzinfo=UTC),
                is_draw=False,
            ),
            # 2. True draw — equal nonzero game wins, no match winner.
            analytics_client.AdminMatchItem(
                match_id="00000000-0000-0000-0000-000000000002",
                user_id=42,
                user_email="alice@local",
                format_="Modern",
                players=["alice", "bob"],
                match_result=None,
                winner=None,
                game_count=2,
                played_at=datetime(2026, 5, 22, 13, 0, tzinfo=UTC),
                is_draw=True,
            ),
            # 3. Partial parse (would have been "Draw" under the old
            # template) — no winner, no draw detection, should render "—".
            analytics_client.AdminMatchItem(
                match_id="00000000-0000-0000-0000-000000000003",
                user_id=42,
                user_email="alice@local",
                format_="Modern",
                players=["alice", "bob"],
                match_result=None,
                winner=None,
                game_count=1,
                played_at=datetime(2026, 5, 22, 14, 0, tzinfo=UTC),
                is_draw=False,
            ),
        ],
        total=3,
        page=1,
        per_page=20,
    )


@pytest.mark.asyncio
async def test_admin_matches_renders_draw_only_for_true_draws(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial-parse match (no winner, no per-game wins) must NOT show
    as "Draw" anymore — it should render an em-dash. A real draw still
    renders "Draw"."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_admin_matches(*_a: Any, **_kw: Any) -> Any:
        return _make_admin_matches()

    monkeypatch.setattr(analytics_client, "admin_list_matches", fake_admin_matches)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_admin()
    try:
        r = await app_client.get("/admin/matches")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.text

    # Decided row: shows the parsed score and the winner in parens.
    assert "2-1" in body
    assert "(alice)" in body

    # The result cell is rendered BEFORE the played-at column that
    # carries the match_id link. So we slice from the start of each
    # row (the <tbody> contains one <tr> per match) up through the
    # match_id and inspect the resulting fragment.
    def _row_fragment(match_id: str) -> str:
        # everything before the match_id link, since the previous </tr>
        # bounds the start of the row that contains this match_id
        head, _, _tail = body.partition(match_id)
        return head.rsplit("<tr", 1)[-1]

    true_draw_row = _row_fragment("00000000-0000-0000-0000-000000000002")
    partial_row = _row_fragment("00000000-0000-0000-0000-000000000003")
    decided_row = _row_fragment("00000000-0000-0000-0000-000000000001")

    # True draw: "Draw" appears in the result cell.
    assert "Draw" in true_draw_row

    # Partial parse (the bug): under the old template this would have
    # rendered "Draw" too. After the fix it must NOT.
    assert "Draw" not in partial_row

    # Decided match: no "Draw" anywhere; shows score + winner.
    assert "Draw" not in decided_row
