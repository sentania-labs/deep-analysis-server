"""``/analytics/stats/matchups`` against a real Postgres (issue #129).

The unit tests in ``services/analytics/tests/test_matchups.py`` patch the
match loader and the archetype lookup. This module runs the SQL that ships:
the hero/opponent joins on ``parser.match_archetypes``, the
``parser.matches.archetype_id`` fallback for the hero, the
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
    legacy_hero_only: bool = False,
    played_at: datetime = datetime(2026, 5, 10, tzinfo=UTC),
) -> uuid.UUID:
    """One 2-game match alice (hero) v bob, with the archetype rows asked for.

    ``legacy_hero_only`` writes the hero archetype only to
    ``parser.matches.archetype_id`` (no ``match_archetypes`` hero row), the
    shape of matches parsed before migration 020.
    """
    match_id = (
        await conn.execute(
            text(
                """
                INSERT INTO parser.matches
                    (sha256, user_id, format, players, hero_player_name, played_at,
                     review_status, archetype_id)
                VALUES (:sha, :uid, 'Modern', CAST(:players AS jsonb), 'alice', :played_at,
                        :review, :legacy)
                RETURNING id
                """
            ),
            {
                "sha": uuid.uuid4().hex + uuid.uuid4().hex,
                "uid": user_id,
                "players": '["alice", "bob"]',
                "played_at": played_at,
                "review": review_status,
                "legacy": hero_arch if legacy_hero_only else None,
            },
        )
    ).scalar_one()
    winners = ["alice", "alice"] if hero_won else ["bob", "bob"]
    for n, winner in enumerate(winners, start=1):
        await conn.execute(
            text("INSERT INTO parser.games (match_id, game_number, winner) VALUES (:m, :n, :w)"),
            {"m": match_id, "n": n, "w": winner},
        )
    sides = [("bob", opp_arch)]
    if not legacy_hero_only:
        sides.append(("alice", hero_arch))
    for player, arch in sides:
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
        # Burn v Tron: 2 wins + 1 loss + 1 legacy-hero win (4 matches).
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["tron"], hero_won=True)
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["tron"], hero_won=True)
        await _seed_match(conn, hero_arch=ids["burn"], opp_arch=ids["tron"], hero_won=False)
        await _seed_match(
            conn,
            hero_arch=ids["burn"],
            opp_arch=ids["tron"],
            hero_won=True,
            legacy_hero_only=True,
        )
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
    # Pending-review, other-user and out-of-range matches are not in the cell;
    # the legacy-hero match (matches.archetype_id fallback) is.
    burn_tron = cells[(burn, tron)]
    assert (burn_tron["matches"], burn_tron["wins"], burn_tron["losses"]) == (4, 3, 1)
    assert burn_tron["win_rate"] == 75.0
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
    assert cell["matches"] == 5  # includes the January match

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
