"""``/analytics/stats/matchups``: hero x opponent archetype matrix (issue #129).

The endpoint reuses ``stats._load_user_matches`` for scoping (user, format,
date, ``review_status IS NULL``) and adds an archetype lookup on top. These
tests patch both seams so they cover the aggregation, the low-sample marker,
the filters and the cache keying without a database.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys-matchups")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(pub_pem)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    yield pub_path


@pytest_asyncio.fixture
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    from analytics_service import main as _main

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _override_user(user_id: int = 7) -> Any:
    from analytics_service import deps as _deps

    fake = _deps.AuthenticatedUser(user_id=user_id, role="user")

    async def _dep() -> _deps.AuthenticatedUser:
        return fake

    return _dep


BURN = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
TRON = uuid.UUID("00000000-0000-0000-0000-0000000000c1")
MURKTIDE = uuid.UUID("00000000-0000-0000-0000-0000000000d1")
ARCH_NAMES = {BURN: "Burn", TRON: "Tron", MURKTIDE: "Murktide"}


def _match(
    fmt: str,
    played_at: datetime,
    wins_by_player: dict[str, int],
    *,
    hero_arch: uuid.UUID | None,
    opp_arch: uuid.UUID | None,
    match_tied: bool = False,
    games: list[str] | None = None,
) -> dict[str, Any]:
    """A match row in the shape ``_load_user_matches`` returns, plus its archetypes.

    ``games`` is the winner of game 1, 2, ... in order; by default it is the
    ``wins_by_player`` tally laid out hero wins first.
    """
    if games is None:
        games = [p for p in ("alice", "bob") for _ in range(wins_by_player.get(p, 0))]
    return {
        "_games": games,
        "id": uuid.uuid4(),
        "format": fmt,
        "players": ["alice", "bob"],
        "played_at": played_at,
        "wins_by_player": wins_by_player,
        "hero_player_name": "alice",
        "match_tied": match_tied,
        "_hero_arch": hero_arch,
        "_opp_arch": opp_arch,
    }


def _win(day: int, hero: uuid.UUID | None = BURN, opp: uuid.UUID | None = TRON) -> dict[str, Any]:
    return _match(
        "Modern",
        datetime(2026, 5, day, tzinfo=UTC),
        {"alice": 2, "bob": 0},
        hero_arch=hero,
        opp_arch=opp,
    )


def _loss(day: int, hero: uuid.UUID | None = BURN, opp: uuid.UUID | None = TRON) -> dict[str, Any]:
    return _match(
        "Modern",
        datetime(2026, 5, day, tzinfo=UTC),
        {"bob": 2, "alice": 1},
        hero_arch=hero,
        opp_arch=opp,
    )


def _patch_data(
    monkeypatch: pytest.MonkeyPatch,
    matches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Replace the match loader and archetype lookup; return the loader's call log.

    The fake loader applies the format and date predicates the SQL does, so a
    filter the endpoint forgets to pass down shows up as wrong numbers.
    """
    from analytics_service import matchups as _matchups

    calls: list[dict[str, Any]] = []

    async def fake_loader(
        _db: Any,
        user_id: int,
        *,
        date_from: date | None = None,
        date_to: date | None = None,
        format_: str | None = None,
        opponent: str | None = None,
    ) -> list[dict[str, Any]]:
        calls.append(
            {
                "user_id": user_id,
                "date_from": date_from,
                "date_to": date_to,
                "format_": format_,
                "opponent": opponent,
            }
        )
        out = matches
        if format_:
            out = [m for m in out if (m["format"] or "").lower() == format_.lower()]
        if date_from:
            out = [m for m in out if m["played_at"].date() >= date_from]
        if date_to:
            out = [m for m in out if m["played_at"].date() <= date_to]
        return out

    async def fake_archetypes(_db: Any, match_ids: list[Any]) -> dict[Any, Any]:
        by_id = {m["id"]: m for m in matches}

        def side(arch: uuid.UUID | None) -> tuple[uuid.UUID, str] | None:
            return (arch, ARCH_NAMES[arch]) if arch else None

        return {
            mid: (side(by_id[mid]["_hero_arch"]), side(by_id[mid]["_opp_arch"]))
            for mid in match_ids
        }

    async def fake_game_winners(_db: Any, match_ids: list[Any]) -> dict[Any, Any]:
        by_id = {m["id"]: m for m in matches}
        return {
            mid: [(n, w) for n, w in enumerate(by_id[mid]["_games"], start=1)] for mid in match_ids
        }

    monkeypatch.setattr(_matchups, "_load_game_winners", fake_game_winners)
    monkeypatch.setattr(_matchups, "_load_user_matches", fake_loader)
    monkeypatch.setattr(_matchups, "_load_match_archetypes", fake_archetypes)
    return calls


def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from analytics_service import matchups as _matchups

    async def _none() -> None:
        return None

    monkeypatch.setattr(_matchups, "_get_redis_or_none", _none)


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value


def _patch_redis(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    from analytics_service import matchups as _matchups

    async def _get() -> _FakeRedis:
        return fake

    monkeypatch.setattr(_matchups, "_get_redis_or_none", _get)


async def _get_matchups(app_client: httpx.AsyncClient, **params: Any) -> dict[str, Any]:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/matchups", params=params)
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 200, r.text
    return r.json()


def _cell(body: dict[str, Any], hero: str, opp: str) -> dict[str, Any]:
    (found,) = [
        c for c in body["cells"] if c["hero_archetype"] == hero and c["opponent_archetype"] == opp
    ]
    return found


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_matrix_aggregates_each_archetype_pair(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_data(
        monkeypatch,
        [
            _win(1),
            _win(2),
            _loss(3),
            _win(4, opp=MURKTIDE),
            _loss(5, hero=TRON, opp=BURN),
        ],
    )
    _no_redis(monkeypatch)

    body = await _get_matchups(app_client)

    assert body["unclassified_matches"] == 0
    assert body["min_sample"] == 5
    burn_tron = _cell(body, "Burn", "Tron")
    assert (burn_tron["matches"], burn_tron["wins"], burn_tron["losses"]) == (3, 2, 1)
    assert burn_tron["decided"] == 3
    assert burn_tron["win_rate"] == pytest.approx(200 / 3)
    assert burn_tron["hero_archetype_id"] == str(BURN)
    assert burn_tron["opponent_archetype_id"] == str(TRON)
    burn_murktide = _cell(body, "Burn", "Murktide")
    assert (burn_murktide["matches"], burn_murktide["win_rate"]) == (1, 100.0)
    # The reverse pairing is a separate cell: the matrix is hero x opponent.
    tron_burn = _cell(body, "Tron", "Burn")
    assert (tron_burn["matches"], tron_burn["losses"], tron_burn["win_rate"]) == (1, 1, 0.0)
    # Busiest cell first.
    assert body["cells"][0]["hero_archetype"] == "Burn"
    assert body["cells"][0]["opponent_archetype"] == "Tron"


@pytest.mark.asyncio
async def test_draws_count_as_matches_but_not_in_win_rate(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same convention as /by-opponent: win rate is wins / (wins + losses)."""
    draw = _match(
        "Modern",
        datetime(2026, 5, 3, tzinfo=UTC),
        {"alice": 1, "bob": 1},
        hero_arch=BURN,
        opp_arch=TRON,
    )
    _patch_data(monkeypatch, [_win(1), draw])
    _no_redis(monkeypatch)

    cell = _cell(await _get_matchups(app_client), "Burn", "Tron")

    assert (cell["matches"], cell["wins"], cell["losses"], cell["draws"]) == (2, 1, 0, 1)
    assert cell["decided"] == 1
    assert cell["win_rate"] == 100.0


@pytest.mark.asyncio
async def test_matches_without_both_archetypes_are_counted_as_unclassified(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_data(
        monkeypatch,
        [_win(1), _win(2, opp=None), _win(3, hero=None), _win(4, hero=None, opp=None)],
    )
    _no_redis(monkeypatch)

    body = await _get_matchups(app_client)

    assert body["unclassified_matches"] == 3
    assert [(c["hero_archetype"], c["matches"]) for c in body["cells"]] == [("Burn", 1)]


@pytest.mark.asyncio
async def test_empty_history_returns_empty_matrix(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_data(monkeypatch, [])
    _no_redis(monkeypatch)

    body = await _get_matchups(app_client)

    assert body == {"min_sample": 5, "cells": [], "unclassified_matches": 0}


# ---------------------------------------------------------------------------
# Low-sample marker and confidence interval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_low_sample_flag_flips_at_the_minimum(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    thin = [_win(d) for d in range(1, 5)]  # 4 decided: below the minimum
    enough = [_win(d, opp=MURKTIDE) for d in range(1, 6)]  # 5 decided: at the minimum
    _patch_data(monkeypatch, thin + enough)
    _no_redis(monkeypatch)

    body = await _get_matchups(app_client)

    assert _cell(body, "Burn", "Tron")["low_sample"] is True
    assert _cell(body, "Burn", "Murktide")["low_sample"] is False


@pytest.mark.asyncio
async def test_low_sample_counts_decided_matches_not_draws(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    draws = [
        _match(
            "Modern",
            datetime(2026, 5, d, tzinfo=UTC),
            {"alice": 1, "bob": 1},
            hero_arch=BURN,
            opp_arch=TRON,
        )
        for d in range(1, 5)
    ]
    _patch_data(monkeypatch, [_win(9), *draws])  # 5 matches, 1 decided
    _no_redis(monkeypatch)

    cell = _cell(await _get_matchups(app_client), "Burn", "Tron")

    assert cell["matches"] == 5
    assert cell["low_sample"] is True


def test_wilson_interval_brackets_the_win_rate_and_tightens_with_sample() -> None:
    from analytics_service.matchups import _wilson_interval

    assert _wilson_interval(0, 0) == (0.0, 0.0)
    low, high = _wilson_interval(3, 4)
    assert low < 75.0 < high
    # Same 75% rate over ten times the sample gives a narrower interval.
    low_big, high_big = _wilson_interval(30, 40)
    assert (high_big - low_big) < (high - low)
    # A perfect record is not reported as certain.
    low_all, high_all = _wilson_interval(5, 5)
    assert 0.0 < low_all < 100.0
    assert high_all == pytest.approx(100.0)


@pytest.mark.asyncio
async def test_cells_carry_the_interval(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_data(monkeypatch, [_win(1), _win(2), _win(3), _loss(4)])
    _no_redis(monkeypatch)

    cell = _cell(await _get_matchups(app_client), "Burn", "Tron")

    assert cell["win_rate_low"] < cell["win_rate"] < cell["win_rate_high"]


# ---------------------------------------------------------------------------
# Scoping and filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scoped_to_the_caller_and_filters_reach_the_loader(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_data(monkeypatch, [_win(1)])
    _no_redis(monkeypatch)

    await _get_matchups(app_client, format="Modern", date_from="2026-05-01", date_to="2026-05-31")

    assert calls == [
        {
            "user_id": 7,
            "date_from": date(2026, 5, 1),
            "date_to": date(2026, 5, 31),
            "format_": "Modern",
            "opponent": None,
        }
    ]


@pytest.mark.asyncio
async def test_format_all_is_no_filter(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_data(monkeypatch, [_win(1)])
    _no_redis(monkeypatch)

    await _get_matchups(app_client, format="all")

    assert calls[0]["format_"] is None


@pytest.mark.asyncio
async def test_format_and_date_filters_narrow_the_matrix(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    pioneer = _match(
        "Pioneer",
        datetime(2026, 5, 2, tzinfo=UTC),
        {"alice": 2},
        hero_arch=BURN,
        opp_arch=MURKTIDE,
    )
    _patch_data(monkeypatch, [_win(1), _win(20), pioneer])
    _no_redis(monkeypatch)

    modern_early = await _get_matchups(app_client, format="Modern", date_to="2026-05-10")
    assert [(c["opponent_archetype"], c["matches"]) for c in modern_early["cells"]] == [("Tron", 1)]

    pioneer_only = await _get_matchups(app_client, format="Pioneer")
    assert [(c["opponent_archetype"], c["matches"]) for c in pioneer_only["cells"]] == [
        ("Murktide", 1)
    ]


@pytest.mark.asyncio
async def test_hero_and_opponent_archetype_filters(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_data(
        monkeypatch,
        [_win(1), _win(2, opp=MURKTIDE), _loss(3, hero=TRON, opp=BURN), _win(4, hero=None)],
    )
    _no_redis(monkeypatch)

    by_hero = await _get_matchups(app_client, hero_archetype_id=str(BURN))
    assert {(c["hero_archetype"], c["opponent_archetype"]) for c in by_hero["cells"]} == {
        ("Burn", "Tron"),
        ("Burn", "Murktide"),
    }
    # Matches an archetype filter dropped are not "unclassified"; the
    # hero-less match is.
    assert by_hero["unclassified_matches"] == 1

    by_opp = await _get_matchups(app_client, opponent_archetype_id=str(TRON))
    assert [(c["hero_archetype"], c["opponent_archetype"]) for c in by_opp["cells"]] == [
        ("Burn", "Tron")
    ]

    both = await _get_matchups(
        app_client, hero_archetype_id=str(BURN), opponent_archetype_id=str(MURKTIDE)
    )
    assert [(c["hero_archetype"], c["opponent_archetype"]) for c in both["cells"]] == [
        ("Burn", "Murktide")
    ]


@pytest.mark.asyncio
async def test_invalid_archetype_id_is_rejected(app_client: httpx.AsyncClient) -> None:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get(
            "/analytics/stats/matchups", params={"hero_archetype_id": "not-a-uuid"}
        )
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Cache keying
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_each_filter_facet_gets_its_own_cache_entry(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_data(monkeypatch, [_win(1), _win(2, opp=MURKTIDE)])
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    await _get_matchups(app_client)
    await _get_matchups(app_client, format="Modern")
    await _get_matchups(app_client, date_from="2026-05-02")
    await _get_matchups(app_client, hero_archetype_id=str(BURN))
    await _get_matchups(app_client, opponent_archetype_id=str(TRON))

    assert len(fake.store) == 5
    cell_counts = sorted(len(json.loads(raw)["cells"]) for raw in fake.store.values())
    # unfiltered 2, format=Modern 2, date_from drops the first match 1,
    # hero=Burn 2, opponent=Tron 1.
    assert cell_counts == [1, 1, 2, 2, 2]


@pytest.mark.asyncio
async def test_repeated_request_is_served_from_cache(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_data(monkeypatch, [_win(1)])
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    first = await _get_matchups(app_client, format="Modern")
    second = await _get_matchups(app_client, format="modern")

    assert first == second
    assert len(fake.store) == 1
    assert len(calls) == 1  # format is case-folded in the key: second call never loaded


# ---------------------------------------------------------------------------
# Pre-board (game 1) vs post-board (games 2+) split
# ---------------------------------------------------------------------------


def _bo3(day: int, games: list[str], opp: uuid.UUID = TRON) -> dict[str, Any]:
    wins = {"alice": games.count("alice"), "bob": games.count("bob")}
    return _match(
        "Modern",
        datetime(2026, 5, day, tzinfo=UTC),
        wins,
        hero_arch=BURN,
        opp_arch=opp,
        games=games,
    )


@pytest.mark.asyncio
async def test_split_counts_game_one_apart_from_later_games(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_redis(monkeypatch)
    _patch_data(
        monkeypatch,
        [
            _bo3(1, ["alice", "bob", "alice"]),  # G1 W; G2 L, G3 W
            _bo3(2, ["bob", "alice", "alice"]),  # G1 L; G2 W, G3 W
            _bo3(3, ["alice", "alice"]),  # G1 W; G2 W
        ],
    )

    body = await _get_matchups(app_client)

    (cell,) = body["cells"]
    assert cell["matches"] == 3
    pre, post = cell["preboard"], cell["postboard"]
    assert (pre["games"], pre["wins"], pre["losses"]) == (3, 2, 1)
    assert pre["win_rate"] == pytest.approx(200 / 3)
    assert (post["games"], post["wins"], post["losses"]) == (5, 4, 1)
    assert post["win_rate"] == pytest.approx(80.0)
    # Splits are game-level; the cell's match-level numbers are unchanged.
    assert (cell["wins"], cell["losses"]) == (3, 0)
    assert pre["win_rate_low"] < pre["win_rate"] < pre["win_rate_high"]


@pytest.mark.asyncio
async def test_match_with_only_game_one_has_empty_postboard(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_redis(monkeypatch)
    _patch_data(monkeypatch, [_bo3(1, ["alice"])])

    (cell,) = (await _get_matchups(app_client))["cells"]

    assert cell["preboard"]["games"] == 1
    assert cell["postboard"] == {
        "games": 0,
        "wins": 0,
        "losses": 0,
        "win_rate": 0.0,
        "win_rate_low": 0.0,
        "win_rate_high": 0.0,
        "low_sample": True,
    }


@pytest.mark.asyncio
async def test_match_with_no_game_rows_gives_empty_splits(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_redis(monkeypatch)
    _patch_data(
        monkeypatch,
        [_match("Modern", datetime(2026, 5, 1, tzinfo=UTC), {}, hero_arch=BURN, opp_arch=TRON)],
    )

    (cell,) = (await _get_matchups(app_client))["cells"]

    assert cell["matches"] == 1
    assert cell["preboard"]["games"] == 0
    assert cell["postboard"]["games"] == 0
    assert cell["preboard"]["low_sample"] and cell["postboard"]["low_sample"]


@pytest.mark.asyncio
async def test_each_split_is_low_sample_on_its_own_game_count(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from analytics_service.matchups import MATCHUP_MIN_SAMPLE

    _no_redis(monkeypatch)
    # MATCHUP_MIN_SAMPLE matches: G1 hits the threshold exactly, while one
    # match ends after G1, so post-board sits one game under it.
    matches = [_bo3(d + 1, ["alice", "alice"]) for d in range(MATCHUP_MIN_SAMPLE - 1)]
    matches.append(_bo3(MATCHUP_MIN_SAMPLE, ["alice"]))
    _patch_data(monkeypatch, matches)

    (cell,) = (await _get_matchups(app_client))["cells"]

    assert cell["preboard"]["games"] == MATCHUP_MIN_SAMPLE
    assert cell["preboard"]["low_sample"] is False
    assert cell["postboard"]["games"] == MATCHUP_MIN_SAMPLE - 1
    assert cell["postboard"]["low_sample"] is True


@pytest.mark.asyncio
async def test_split_is_per_cell_and_follows_the_hero_not_the_player_order(
    app_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_redis(monkeypatch)
    flipped = _bo3(1, ["bob", "bob"], opp=MURKTIDE)
    flipped["hero_player_name"] = "bob"  # bob is the hero in this match
    flipped["players"] = ["alice", "bob"]
    _patch_data(monkeypatch, [_bo3(2, ["alice", "bob", "bob"]), flipped])

    cells = {c["opponent_archetype"]: c for c in (await _get_matchups(app_client))["cells"]}

    assert cells["Tron"]["preboard"]["wins"] == 1
    assert (cells["Tron"]["postboard"]["wins"], cells["Tron"]["postboard"]["losses"]) == (0, 2)
    assert (cells["Murktide"]["preboard"]["wins"], cells["Murktide"]["postboard"]["wins"]) == (1, 1)
