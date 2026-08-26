"""Filter and cache behaviour for ``/analytics/stats/by-opponent`` (issue #124).

The Match History page renders the opponent aggregates next to a filtered
match list, so the aggregates have to be computed from the same set of
matches. These tests cover three things:

1. A filtered request aggregates only the matching matches.
2. An unfiltered request behaves exactly as it did before (regression guard).
3. Filtered and unfiltered responses never share a cache entry.

The cache key already hashes its ``**filters`` kwargs (``common.cache.cache_key``),
so the risk is not the hashing but the endpoint forgetting to pass the filters
in. That is what the cache tests below pin down.
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
    out = tmp_path_factory.mktemp("analytics-jwt-keys-by-opponent")
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


def _match(
    fmt: str,
    players: list[str],
    played_at: datetime,
    wins_by_player: dict[str, int],
    *,
    match_tied: bool = False,
) -> dict[str, Any]:
    """A match row in the shape ``_load_user_matches`` returns."""
    return {
        "id": uuid.uuid4(),
        "format": fmt,
        "players": players,
        "played_at": played_at,
        "wins_by_player": wins_by_player,
        "hero_player_name": players[0],
        "match_tied": match_tied,
    }


# The fixture set: hero "alice" plays bob in Modern (1 win, 1 loss) and
# carol in Pioneer (1 win). The Modern loss is in April, everything else May.
_MATCHES = [
    _match("Modern", ["alice", "bob"], datetime(2026, 5, 9, tzinfo=UTC), {"alice": 2, "bob": 0}),
    _match("Modern", ["alice", "bob"], datetime(2026, 4, 8, tzinfo=UTC), {"bob": 2, "alice": 1}),
    _match("Pioneer", ["alice", "carol"], datetime(2026, 5, 7, tzinfo=UTC), {"alice": 2}),
]


def _patch_filtering_loader(
    monkeypatch: pytest.MonkeyPatch,
    matches: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Replace ``_load_user_matches`` with a fake that really filters.

    The fake applies the same format / opponent / date predicates the SQL
    does, so an endpoint that forgets to pass a filter through shows up as
    wrong aggregate numbers rather than a silently ignored argument. The
    returned list records every call for direct argument assertions.
    """
    from analytics_service import stats as _stats

    rows = _MATCHES if matches is None else matches
    calls: list[dict[str, Any]] = []

    async def fake_loader(
        _db: Any,
        _user_id: int,
        *,
        date_from: date | None = None,
        date_to: date | None = None,
        format_: str | None = None,
        opponent: str | None = None,
    ) -> list[dict[str, Any]]:
        calls.append(
            {
                "date_from": date_from,
                "date_to": date_to,
                "format_": format_,
                "opponent": opponent,
            }
        )
        out = rows
        if format_:
            out = [m for m in out if (m["format"] or "").lower() == format_.lower()]
        if opponent:
            needle = opponent.lower()
            out = [m for m in out if any(needle in str(p).lower() for p in m["players"])]
        if date_from:
            out = [m for m in out if m["played_at"].date() >= date_from]
        if date_to:
            out = [m for m in out if m["played_at"].date() <= date_to]
        return out

    monkeypatch.setattr(_stats, "_load_user_matches", fake_loader)
    return calls


def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    from analytics_service import stats as _stats

    async def _none() -> None:
        return None

    monkeypatch.setattr(_stats, "_get_redis_or_none", _none)


class _FakeRedis:
    """Dict-backed stand-in for the bits of Redis the cache layer uses."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.gets: list[str] = []

    async def get(self, key: str) -> str | None:
        self.gets.append(key)
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value


def _patch_redis(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    from analytics_service import stats as _stats

    async def _get() -> _FakeRedis:
        return fake

    monkeypatch.setattr(_stats, "_get_redis_or_none", _get)


async def _get_by_opponent(app_client: httpx.AsyncClient, **params: Any) -> list[dict[str, Any]]:
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/by-opponent", params=params)
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Regression guard: unfiltered behaviour is unchanged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unfiltered_matches_previous_behaviour(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client)

    by_opp = {row["opponent"]: row for row in rows}
    assert by_opp["bob"]["matches"] == 2
    assert by_opp["bob"]["wins"] == 1
    assert by_opp["bob"]["losses"] == 1
    assert by_opp["bob"]["win_rate"] == 50.0
    assert by_opp["carol"]["matches"] == 1
    assert by_opp["carol"]["wins"] == 1
    assert by_opp["carol"]["win_rate"] == 100.0
    # No filters given means no filters pushed down.
    assert calls == [{"date_from": None, "date_to": None, "format_": None, "opponent": None}]


@pytest.mark.asyncio
async def test_all_sentinels_are_treated_as_no_filter(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``format=all`` / ``result=all`` are the template's "no filter" values."""
    calls = _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client, format="all", result="all")

    assert {row["opponent"] for row in rows} == {"bob", "carol"}
    assert calls[0]["format_"] is None


# ---------------------------------------------------------------------------
# Filtered aggregates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_format_filter_narrows_aggregates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client, format="Pioneer")

    assert calls[0]["format_"] == "Pioneer"
    assert [row["opponent"] for row in rows] == ["carol"]
    assert rows[0]["matches"] == 1


@pytest.mark.asyncio
async def test_date_range_narrows_aggregates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """May-only view drops the April Modern loss to bob."""
    calls = _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client, date_from="2026-05-01", date_to="2026-05-31")

    assert calls[0]["date_from"] == date(2026, 5, 1)
    assert calls[0]["date_to"] == date(2026, 5, 31)
    by_opp = {row["opponent"]: row for row in rows}
    assert by_opp["bob"]["matches"] == 1
    assert by_opp["bob"]["wins"] == 1
    assert by_opp["bob"]["losses"] == 0
    assert by_opp["bob"]["win_rate"] == 100.0


@pytest.mark.asyncio
async def test_opponent_search_narrows_aggregates(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client, opponent="car")

    assert calls[0]["opponent"] == "car"
    assert [row["opponent"] for row in rows] == ["carol"]


@pytest.mark.asyncio
async def test_result_filter_counts_only_matching_results(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``result=losses`` leaves only the one match bob won."""
    _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client, result="losses")

    assert [row["opponent"] for row in rows] == ["bob"]
    assert rows[0]["matches"] == 1
    assert rows[0]["losses"] == 1
    assert rows[0]["wins"] == 0
    assert rows[0]["win_rate"] == 0.0


@pytest.mark.asyncio
async def test_combined_filters_can_empty_the_table(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_filtering_loader(monkeypatch)
    _no_redis(monkeypatch)

    rows = await _get_by_opponent(app_client, format="Pioneer", result="losses")

    assert rows == []


# ---------------------------------------------------------------------------
# Cache correctness: the highest-risk part of the change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filtered_request_does_not_read_unfiltered_cache(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_filtering_loader(monkeypatch)
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    unfiltered = await _get_by_opponent(app_client)
    assert {row["opponent"] for row in unfiltered} == {"bob", "carol"}
    assert len(fake.store) == 1  # unfiltered result is now cached

    filtered = await _get_by_opponent(app_client, format="Pioneer")
    assert [row["opponent"] for row in filtered] == ["carol"]
    assert len(fake.store) == 2  # separate entry, not a hit on the unfiltered one


@pytest.mark.asyncio
async def test_unfiltered_request_does_not_read_filtered_cache(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_filtering_loader(monkeypatch)
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    filtered = await _get_by_opponent(app_client, format="Pioneer")
    assert [row["opponent"] for row in filtered] == ["carol"]

    unfiltered = await _get_by_opponent(app_client)
    assert {row["opponent"] for row in unfiltered} == {"bob", "carol"}


@pytest.mark.asyncio
async def test_each_filter_facet_gets_its_own_cache_entry(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two different filter sets must not collide on one key."""
    _patch_filtering_loader(monkeypatch)
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    await _get_by_opponent(app_client, format="Modern")
    await _get_by_opponent(app_client, format="Pioneer")
    await _get_by_opponent(app_client, date_from="2026-05-01")
    await _get_by_opponent(app_client, opponent="bob")
    await _get_by_opponent(app_client, result="losses")

    assert len(fake.store) == 5
    # And every entry holds the answer for its own filter, not another's:
    # exactly one cached payload is the single-carol Pioneer answer, and
    # exactly one is the bob-only answer the opponent search produces.
    payloads = [json.loads(raw) for raw in fake.store.values()]
    shapes = sorted(
        tuple(sorted((row["opponent"], row["matches"]) for row in payload)) for payload in payloads
    )
    assert shapes == sorted(
        [
            (("bob", 2),),  # format=Modern
            (("carol", 1),),  # format=Pioneer
            (("bob", 1), ("carol", 1)),  # date_from=2026-05-01
            (("bob", 2),),  # opponent=bob
            (("bob", 1),),  # result=losses
        ]
    )


@pytest.mark.asyncio
async def test_repeated_identical_request_hits_the_cache(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_filtering_loader(monkeypatch)
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    first = await _get_by_opponent(app_client, format="Modern", date_from="2026-05-01")
    second = await _get_by_opponent(app_client, format="Modern", date_from="2026-05-01")

    assert first == second
    assert len(fake.store) == 1
    assert len(calls) == 1  # the second request never reached the loader


@pytest.mark.asyncio
async def test_all_sentinel_shares_the_unfiltered_cache_entry(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalizing before the key means ``format=all`` is not a third variant."""
    _patch_filtering_loader(monkeypatch)
    fake = _FakeRedis()
    _patch_redis(monkeypatch, fake)

    await _get_by_opponent(app_client)
    await _get_by_opponent(app_client, format="all", result="all")

    assert len(fake.store) == 1
    assert next(iter(fake.store)).endswith(":by-opponent:nofilter")


# ---------------------------------------------------------------------------
# Loader SQL: the filters have to reach the WHERE clause
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _CapturingSession:
    """Records the SQL text and bound params of every execute() call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, statement: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        self.calls.append((str(statement), dict(params or {})))
        return _FakeResult([])


@pytest.mark.asyncio
async def test_loader_sql_binds_format_and_opponent() -> None:
    from analytics_service import stats as _stats

    db = _CapturingSession()
    rows = await _stats._load_user_matches(
        db,
        7,
        date_from=date(2026, 5, 1),
        date_to=date(2026, 5, 31),
        format_="Modern",
        opponent="bo_b",
    )

    assert rows == []
    sql, params = db.calls[0]
    assert "LOWER(format) = LOWER(:format)" in sql
    assert "players::text ILIKE :opp_pattern" in sql
    assert params["format"] == "Modern"
    # The underscore is a LIKE wildcard and must be escaped.
    assert params["opp_pattern"] == "%bo\\_b%"
    assert params["date_from"] == date(2026, 5, 1)
    assert params["date_to"] == date(2026, 5, 31)


@pytest.mark.asyncio
async def test_loader_sql_omits_clauses_when_unfiltered() -> None:
    from analytics_service import stats as _stats

    db = _CapturingSession()
    await _stats._load_user_matches(db, 7)

    sql, params = db.calls[0]
    assert "LOWER(format)" not in sql
    assert "opp_pattern" not in sql
    assert params == {"user_id": 7}
