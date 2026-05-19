"""Tests for the /matches/{match_id} detail route.

Bypasses browser auth via FastAPI dependency overrides and patches the
analytics client. Covers the happy path (renders metadata + games),
the 404 path (analytics returned None), the analytics-outage 503, and
the overall W/L/D computation from the games list.
"""

from __future__ import annotations

import uuid
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


def _sample_match(
    *,
    match_id: str,
    games_won_by_uploader: int = 2,
    games_won_by_opponent: int = 1,
    hero: str = "alice",
    opponent: str = "bob",
    players: list[str] | None = None,
) -> Any:
    from web_service import analytics_client

    games: list[Any] = []
    n = 0
    for _ in range(games_won_by_uploader):
        n += 1
        games.append(analytics_client.GameItem(game_number=n, winner=hero, turns=7))
    for _ in range(games_won_by_opponent):
        n += 1
        games.append(analytics_client.GameItem(game_number=n, winner=opponent, turns=10))
    return analytics_client.MatchDetail(
        match_id=match_id,
        format_="Modern",
        players=players if players is not None else [hero, opponent],
        played_at=datetime(2026, 5, 9, 12, 0, tzinfo=UTC),
        hero_player_name=hero,
        games=games,
    )


@pytest.mark.asyncio
async def test_match_detail_renders(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_detail(_url: str, _token: str, mid: str) -> Any:
        assert mid == match_id
        return _sample_match(match_id=match_id)

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    text = r.text
    # Title uses first 8 chars of the match id.
    assert match_id[:8] in text
    assert "Modern" in text
    assert "alice" in text
    assert "bob" in text
    # Three games rendered (2W, 1L) → overall W.
    assert "result-win" in text


@pytest.mark.asyncio
async def test_match_detail_overall_loss(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_detail(_url: str, _token: str, _mid: str) -> Any:
        return _sample_match(
            match_id=match_id,
            games_won_by_uploader=0,
            games_won_by_opponent=2,
        )

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "result-loss" in r.text


@pytest.mark.asyncio
async def test_match_detail_uses_hero_player_name_not_players0(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test: hero as players[1] must not invert W/L."""
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_detail(_url: str, _token: str, mid: str) -> Any:
        assert mid == match_id
        return _sample_match(
            match_id=match_id,
            games_won_by_uploader=2,
            games_won_by_opponent=1,
            hero="alice",
            opponent="bob",
            players=["bob", "alice"],
        )

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)
    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "result-win" in r.text
    assert "result-loss" not in r.text


@pytest.mark.asyncio
async def test_match_detail_404_when_analytics_returns_none(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def fake_detail(*_a: Any, **_kw: Any) -> Any:
        return None

    monkeypatch.setattr(analytics_client, "get_match_detail", fake_detail)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{uuid.uuid4()}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 404
    assert "Match not found" in r.text


@pytest.mark.asyncio
async def test_match_detail_503_when_analytics_unavailable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "get_match_detail", boom)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{uuid.uuid4()}")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_match_detail_malformed_id_returns_422(app_client: httpx.AsyncClient) -> None:
    from web_service import deps as _deps
    from web_service import main as _main

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get("/matches/not-a-uuid")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 422


@pytest.mark.asyncio
async def test_match_detail_unauth_redirects_to_login(app_client: httpx.AsyncClient) -> None:
    r = await app_client.get(f"/matches/{uuid.uuid4()}")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


# ---------------------------------------------------------------------------
# Turn viewer HTMX partial
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_turn_viewer_renders_turns(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_turns(_url: str, _token: str, _mid: str, _gn: int) -> Any:
        return analytics_client.GameTurnsResponse(
            match_id=match_id,
            game_number=1,
            turns=[
                analytics_client.TurnData(
                    turn_number=1,
                    active_player="alice",
                    player_states=[
                        analytics_client.PlayerTurnState(
                            player="alice",
                            life=20,
                            zones=analytics_client.ZoneState(
                                battlefield=["Mountain"],
                                hand=["Lightning Bolt"],
                            ),
                        ),
                        analytics_client.PlayerTurnState(
                            player="bob",
                            life=20,
                        ),
                    ],
                ),
                analytics_client.TurnData(
                    turn_number=2,
                    active_player="bob",
                    player_states=[
                        analytics_client.PlayerTurnState(player="alice", life=20),
                        analytics_client.PlayerTurnState(player="bob", life=17),
                    ],
                ),
            ],
        )

    monkeypatch.setattr(analytics_client, "get_game_turns", fake_turns)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    text = r.text
    # Partial — no full HTML doc
    assert "<!DOCTYPE" not in text
    # Contains turn data
    assert "alice" in text
    assert "bob" in text
    assert "Mountain" in text
    assert "Lightning Bolt" in text


@pytest.mark.asyncio
async def test_turn_viewer_empty_turns(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    match_id = str(uuid.uuid4())

    async def fake_turns(_url: str, _token: str, _mid: str, _gn: int) -> Any:
        return analytics_client.GameTurnsResponse(
            match_id=match_id,
            game_number=1,
            turns=[],
        )

    monkeypatch.setattr(analytics_client, "get_game_turns", fake_turns)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{match_id}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    assert "No turn data available" in r.text


@pytest.mark.asyncio
async def test_turn_viewer_503_when_analytics_unavailable(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def boom(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsClientError("simulated outage")

    monkeypatch.setattr(analytics_client, "get_game_turns", boom)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{uuid.uuid4()}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 503
    assert "Turn data unavailable" in r.text


@pytest.mark.asyncio
async def test_turn_viewer_unauth_returns_401(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from web_service import analytics_client
    from web_service import deps as _deps
    from web_service import main as _main

    async def forbidden(*_a: Any, **_kw: Any) -> Any:
        raise analytics_client.AnalyticsForbidden("expired")

    monkeypatch.setattr(analytics_client, "get_game_turns", forbidden)

    _main.app.dependency_overrides[_deps.get_current_browser_user] = _override_user()
    try:
        r = await app_client.get(f"/matches/{uuid.uuid4()}/games/1/turns")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 401
