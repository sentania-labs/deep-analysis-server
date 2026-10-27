"""``/analytics/stats/matchups`` against a real Postgres (issue #129).

The unit tests in ``services/analytics/tests/test_matchups.py`` patch the
match loader and the archetype lookup. This module runs the SQL that ships:
the hero/opponent joins on ``parser.match_archetypes``, the
``review_status IS NULL`` exclusion and the per-user scoping.

Skipped unless ``DA_DATABASE_URL`` (async driver) is set; CI sets it and runs
``alembic upgrade head`` before pytest.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

USER = 987_001
OTHER_USER = 987_002


def _url() -> str | None:
    return os.environ.get("DA_DATABASE_URL") or os.environ.get("DA_TEST_DATABASE_URL")


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    url = _url()
    if not url:
        pytest.skip("DA_DATABASE_URL not set, skipping matchups SQL round-trip")
    eng = create_async_engine(url)
    try:
        yield eng
    finally:
        await eng.dispose()


async def _seed_archetype(conn: Any, name: str) -> uuid.UUID:
    return (
        await conn.execute(
            text(
                "INSERT INTO analytics.archetypes (name, format) VALUES (:n, 'Modern') RETURNING id"
            ),
            {"n": f"pytest-{name}-{uuid.uuid4().hex[:6]}"},
        )
    ).scalar_one()


async def _seed_match(
    conn: Any,
    *,
    user_id: int = USER,
    hero_arch: uuid.UUID | None,
    opp_arch: uuid.UUID | None,
    hero_won: bool,
    review_status: str | None = None,
    played_at: datetime = datetime(2026, 5, 10, tzinfo=UTC),
    winners: list[str] | None = None,
) -> uuid.UUID:
    """One match alice (hero) v bob, with the archetype rows asked for.

    ``winners`` lists the winner of game 1, 2, ...; by default a 2-0 for whoever
    ``hero_won`` says.
    """
    match_id = (
        await conn.execute(
            text(
                """
                INSERT INTO parser.matches
                    (sha256, user_id, format, players, hero_player_name, played_at,
                     review_status)
                VALUES (:sha, :uid, 'Modern', CAST(:players AS jsonb), 'alice', :played_at,
                        :review)
                RETURNING id
                """
            ),
            {
                "sha": uuid.uuid4().hex + uuid.uuid4().hex,
                "uid": user_id,
                "players": '["alice", "bob"]',
                "played_at": played_at,
                "review": review_status,
            },
        )
    ).scalar_one()
    if winners is None:
        winners = ["alice", "alice"] if hero_won else ["bob", "bob"]
    for n, winner in enumerate(winners, start=1):
        await conn.execute(
            text("INSERT INTO parser.games (match_id, game_number, winner) VALUES (:m, :n, :w)"),
            {"m": match_id, "n": n, "w": winner},
        )
    for player, arch in (("alice", hero_arch), ("bob", opp_arch)):
        if arch is not None:
            await conn.execute(
                text(
                    "INSERT INTO parser.match_archetypes (match_id, player_name, archetype_id) "
                    "VALUES (:m, :p, :a)"
                ),
                {"m": match_id, "p": player, "a": arch},
            )
    return match_id  # type: ignore[no-any-return]


@pytest.fixture
async def seeded(engine: AsyncEngine) -> AsyncIterator[dict[str, uuid.UUID]]:
    async with engine.begin() as conn:
        ids = {
            "burn": await _seed_archetype(conn, "burn"),
            "tron": await _seed_archetype(conn, "tron"),
            "murktide": await _seed_archetype(conn, "murktide"),
        }
        # Burn v Tron: 2 wins + 1 loss (3 matches).
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["tron"], hero_won=True)
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["tron"], hero_won=True)
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["tron"], hero_won=False)
        # Burn v Murktide: one loss.
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["murktide"], hero_won=False)
        # Excluded or uncounted: pending review, another user's, and no opponent archetype.
        await _seed_match(
            conn,
            hero_arch=ids["burn"],
            opp_arch=ids["tron"],
            hero_won=True,
            review_status="pending_review",
        )
        await _seed_match(
            conn,
            user_id=OTHER_USER,
            hero_arch=ids["burn"],
            opp_arch=ids["tron"],
            hero_won=True,
        )
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=None, hero_won=True)
        # Outside the date filter used below.
        await _seed_match(
            conn,
            hero_arch=ids["burn"],
            opp_arch=ids["tron"],
            hero_won=True,
            played_at=datetime(2026, 1, 5, tzinfo=UTC),
        )
    try:
        yield ids
    finally:
        async with engine.begin() as conn:
            # match_archetypes and games cascade from parser.matches.
            await conn.execute(
                text("DELETE FROM parser.matches WHERE user_id IN (:a, :b)"),
                {"a": USER, "b": OTHER_USER},
            )
            await conn.execute(
                text("DELETE FROM analytics.archetypes WHERE id = ANY(:ids)"),
                {"ids": list(ids.values())},
            )


@pytest.fixture
async def client(engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    pub = os.environ.get("DA_JWT_PUBLIC_KEY_PATH")
    if not pub or not Path(pub).exists():
        pytest.skip("DA_JWT_PUBLIC_KEY_PATH not set")
    from analytics_service import db as _db
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _db.reset_engine()

    async def _user() -> _deps.AuthenticatedUser:
        return _deps.AuthenticatedUser(user_id=USER, role="user")

    _main.app.dependency_overrides[_deps.require_user] = _user
    # Redis is not part of what this test proves; keep the cache out of it.
    from analytics_service import matchups as _matchups

    async def _no_redis() -> None:
        return None

    original = _matchups._get_redis_or_none
    _matchups._get_redis_or_none = _no_redis  # type: ignore[assignment]
    transport = httpx.ASGITransport(app=_main.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        _matchups._get_redis_or_none = original  # type: ignore[assignment]
        _main.app.dependency_overrides.clear()
        _db.reset_engine()


def _by_pair(body: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(c["hero_archetype_id"], c["opponent_archetype_id"]): c for c in body["cells"]}


async def test_matrix_from_real_rows(
    client: httpx.AsyncClient, seeded: dict[str, uuid.UUID]
) -> None:
    r = await client.get("/analytics/stats/matchups", params={"date_from": "2026-05-01"})
    assert r.status_code == 200, r.text
    body = r.json()

    cells = _by_pair(body)
    burn, tron, murktide = (str(seeded[k]) for k in ("burn", "tron", "murktide"))
    # Pending-review, other-user and out-of-range matches are not in the cell.
    burn_tron = cells[(burn, tron)]
    assert (burn_tron["matches"], burn_tron["wins"], burn_tron["losses"]) == (3, 2, 1)
    assert burn_tron["win_rate"] == pytest.approx(200 / 3)
    assert burn_tron["low_sample"] is True
    burn_murktide = cells[(burn, murktide)]
    assert (burn_murktide["matches"], burn_murktide["wins"], burn_murktide["losses"]) == (1, 0, 1)
    assert set(cells) == {(burn, tron), (burn, murktide)}
    # The one in-scope match with no opponent archetype.
    assert body["unclassified_matches"] == 1


async def test_archetype_and_date_filters_against_real_rows(
    client: httpx.AsyncClient, seeded: dict[str, uuid.UUID]
) -> None:
    all_time = await client.get(
        "/analytics/stats/matchups", params={"opponent_archetype_id": str(seeded["tron"])}
    )
    (cell,) = all_time.json()["cells"]
    assert cell["matches"] == 4  # includes the January match

    narrowed = await client.get(
        "/analytics/stats/matchups",
        params={
            "hero_archetype_id": str(seeded["burn"]),
            "opponent_archetype_id": str(seeded["murktide"]),
        },
    )
    (cell,) = narrowed.json()["cells"]
    assert cell["opponent_archetype"].startswith("pytest-murktide-")
    assert cell["matches"] == 1


async def test_split_from_real_rows(client: httpx.AsyncClient, engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        burn = await _seed_archetype(conn, "split-burn")
        tron = await _seed_archetype(conn, "split-tron")
        for winners in (
            ["alice", "bob", "alice"],  # G1 W, G2 L, G3 W
            ["bob", "alice", "alice"],  # G1 L, G2 W, G3 W
            ["alice"],  # ends after G1: no post-board games
        ):
            await _seed_match(conn, hero_arch=burn, opp_arch=tron, hero_won=True, winners=winners)
        # Pending-review and other-user games must not reach either split.
        await _seed_match(
            conn,
            hero_arch=burn,
            opp_arch=tron,
            hero_won=False,
            winners=["bob", "bob", "bob"],
            review_status="pending_review",
        )
        await _seed_match(
            conn,
            user_id=OTHER_USER,
            hero_arch=burn,
            opp_arch=tron,
            hero_won=False,
            winners=["bob", "bob", "bob"],
        )
    try:
        r = await client.get("/analytics/stats/matchups", params={"hero_archetype_id": str(burn)})
        assert r.status_code == 200, r.text
        (cell,) = r.json()["cells"]
        assert cell["matches"] == 3
        pre, post = cell["preboard"], cell["postboard"]
        assert (pre["games"], pre["wins"], pre["losses"]) == (3, 2, 1)
        assert (post["games"], post["wins"], post["losses"]) == (4, 3, 1)
        assert pre["low_sample"] is True and post["low_sample"] is True
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM parser.matches WHERE user_id IN (:a, :b)"),
                {"a": USER, "b": OTHER_USER},
            )
            await conn.execute(
                text("DELETE FROM analytics.archetypes WHERE id = ANY(:ids)"),
                {"ids": [burn, tron]},
            )


async def test_match_list_archetype_filter_matches_the_matrix_cell(
    client: httpx.AsyncClient, seeded: dict[str, uuid.UUID]
) -> None:
    """A cell's drill-down lists exactly the matches the cell counted."""
    params = {
        "hero_archetype_id": str(seeded["burn"]),
        "opponent_archetype_id": str(seeded["tron"]),
        "date_from": "2026-05-01",
    }
    cell = (await client.get("/analytics/stats/matchups", params=params)).json()["cells"][0]
    listing = (await client.get("/analytics/stats/matches", params=params)).json()
    by_opp = (await client.get("/analytics/stats/by-opponent", params=params)).json()

    # Same 3 matches; pending-review, other-user and out-of-range ones stay out.
    assert listing["total"] == cell["matches"] == 3
    assert sum(o["matches"] for o in by_opp) == 3

    only_murktide = await client.get(
        "/analytics/stats/matches",
        params={
            "hero_archetype_id": str(seeded["burn"]),
            "opponent_archetype_id": str(seeded["murktide"]),
        },
    )
    assert only_murktide.json()["total"] == 1

    # An archetype the hero never played narrows to nothing, not to everything.
    unplayed = await client.get(
        "/analytics/stats/matches", params={"hero_archetype_id": str(seeded["tron"])}
    )
    assert unplayed.json()["total"] == 0


async def _seed_card_rows(
    conn: Any, match_id: uuid.UUID, rows: list[tuple[int, str, bool, bool | None]]
) -> None:
    """``analytics.card_game_stats`` rows: ``(game_number, card, is_local, won)``."""
    for game_number, card, is_local, won in rows:
        game_id = (
            await conn.execute(
                text("SELECT id FROM parser.games WHERE match_id = :m AND game_number = :n"),
                {"m": match_id, "n": game_number},
            )
        ).scalar_one()
        await conn.execute(
            text(
                """
                INSERT INTO analytics.card_game_stats
                    (match_id, game_id, card_name, is_local, seen, "cast", played,
                     is_postboard, won, quantity, game_number)
                VALUES (:m, :g, :c, :loc, 1, 1, 0, :post, :won, 1, :n)
                """
            ),
            {
                "m": match_id,
                "g": game_id,
                "c": card,
                "loc": is_local,
                "post": game_number > 1,
                "won": won,
                "n": game_number,
            },
        )


async def test_matchup_cards_from_real_rows(client: httpx.AsyncClient, engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        burn = await _seed_archetype(conn, "cards-burn")
        tron = await _seed_archetype(conn, "cards-tron")
        other = await _seed_archetype(conn, "cards-other")
        m1 = await _seed_match(
            conn, hero_arch=burn, opp_arch=tron, hero_won=True, winners=["bob", "alice", "alice"]
        )
        m2 = await _seed_match(
            conn, hero_arch=burn, opp_arch=tron, hero_won=True, winners=["alice", "bob"]
        )
        await _seed_card_rows(
            conn,
            m1,
            [
                (1, "Bolt", True, False),
                (2, "Bolt", True, True),
                (2, "Rift", True, True),
                (3, "Rift", True, True),
                # Opponent's cards never reach the hero's list.
                (1, "Karn", False, True),
            ],
        )
        await _seed_card_rows(conn, m2, [(1, "Bolt", True, True), (2, "Rift", True, False)])
        # Same pair but excluded: pending review, another user's, another opponent.
        pending = await _seed_match(
            conn, hero_arch=burn, opp_arch=tron, hero_won=True, review_status="pending_review"
        )
        await _seed_card_rows(conn, pending, [(1, "Ghost", True, True)])
        theirs = await _seed_match(
            conn, user_id=OTHER_USER, hero_arch=burn, opp_arch=tron, hero_won=True
        )
        await _seed_card_rows(conn, theirs, [(1, "Ghost", True, True)])
        elsewhere = await _seed_match(conn, hero_arch=burn, opp_arch=other, hero_won=True)
        await _seed_card_rows(conn, elsewhere, [(1, "Ghost", True, True)])
        old = await _seed_match(
            conn,
            hero_arch=burn,
            opp_arch=tron,
            hero_won=True,
            played_at=datetime(2026, 1, 5, tzinfo=UTC),
        )
        await _seed_card_rows(conn, old, [(1, "Ghost", True, True)])
    try:
        params = {
            "hero_archetype_id": str(burn),
            "opponent_archetype_id": str(tron),
            "date_from": "2026-05-01",
        }
        r = await client.get("/analytics/stats/matchups/cards", params=params)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["matches"] == 2
        cards = {c["card_name"]: c for c in body["cards"]}
        assert set(cards) == {"Bolt", "Rift"}
        assert (cards["Bolt"]["games"], cards["Bolt"]["wins"]) == (3, 2)
        assert (cards["Rift"]["games"], cards["Rift"]["wins"]) == (3, 2)
        # Rift is never in a game 1; Bolt is in both matches' game 1.
        (rift,) = body["sideboard"]
        assert rift["card_name"] == "Rift"
        assert (rift["games"], rift["wins"], rift["matches"]) == (3, 2, 2)
        # Post-board pool is m1 G2 W, m1 G3 W, m2 G2 L, all with Rift.
        assert rift["baseline_games"] == 0 and rift["delta"] is None

        # Without the date filter the January match comes in, and only it.
        r = await client.get(
            "/analytics/stats/matchups/cards",
            params={"hero_archetype_id": str(burn), "opponent_archetype_id": str(tron)},
        )
        assert {c["card_name"] for c in r.json()["cards"]} == {"Bolt", "Rift", "Ghost"}
    finally:
        async with engine.begin() as conn:
            # card_game_stats has no FK; clear it by match before the matches go.
            await conn.execute(
                text(
                    "DELETE FROM analytics.card_game_stats WHERE match_id IN "
                    "(SELECT id FROM parser.matches WHERE user_id IN (:a, :b))"
                ),
                {"a": USER, "b": OTHER_USER},
            )
            await conn.execute(
                text("DELETE FROM parser.matches WHERE user_id IN (:a, :b)"),
                {"a": USER, "b": OTHER_USER},
            )
            await conn.execute(
                text("DELETE FROM analytics.archetypes WHERE id = ANY(:ids)"),
                {"ids": [burn, tron, other]},
            )
