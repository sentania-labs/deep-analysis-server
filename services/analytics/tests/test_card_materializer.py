"""Tests for the card_game_stats materializer (analytics_service.card_materializer).

Verifies that:
- materialize_card_game_stats produces correct rows from DB-stored game data
- The Redis subscriber loop retries on disconnect with backoff
- The match.parsed event triggers materialization
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys-materializer")
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


# ---------------------------------------------------------------------------
# Fake DB layer
# ---------------------------------------------------------------------------


class _RowProxy:
    """Mimics SQLAlchemy Row for tuple-unpacking and indexing."""

    def __init__(self, row: tuple[Any, ...]) -> None:
        self._row = row

    def __iter__(self) -> Any:
        return iter(self._row)

    def __len__(self) -> int:
        return len(self._row)

    def __getitem__(self, idx: int) -> Any:
        return self._row[idx]


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[_RowProxy]:
        return [_RowProxy(r) for r in self._rows]

    def one_or_none(self) -> _RowProxy | None:
        if not self._rows:
            return None
        return _RowProxy(self._rows[0])

    def scalar_one_or_none(self) -> Any:
        if not self._rows:
            return None
        return self._rows[0][0] if isinstance(self._rows[0], tuple) else self._rows[0]

    def scalar_one(self) -> Any:
        if not self._rows:
            raise ValueError("No rows")
        return self._rows[0][0] if isinstance(self._rows[0], tuple) else self._rows[0]


class _FakeSession:
    """Returns canned row sets in queue order. Tracks execute calls."""

    def __init__(self, *, queue: list[list[tuple[Any, ...]]]) -> None:
        self._queue = list(queue)
        self.execute_calls: list[dict[str, Any]] = []

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        self.execute_calls.append({"stmt": str(stmt), "params": dict(params or {})})
        rows = self._queue.pop(0) if self._queue else []
        return _FakeResult(rows)

    async def commit(self) -> None:
        pass

    async def rollback(self) -> None:
        pass


# ---------------------------------------------------------------------------
# materialize_card_game_stats tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_materialize_skips_when_no_hero() -> None:
    """Materialization is skipped when hero_player_name is NULL."""
    from analytics_service.card_materializer import materialize_card_game_stats

    session = _FakeSession(
        queue=[
            # hero_player_name lookup -> NULL
            [],
        ]
    )
    await materialize_card_game_stats(session, "test-match-id", user_id=1)
    # Only one query (hero lookup), no INSERT
    assert len(session.execute_calls) == 1
    assert "hero_player_name" in session.execute_calls[0]["stmt"]


@pytest.mark.asyncio
async def test_materialize_skips_when_no_games() -> None:
    """Materialization produces no rows when there are no games."""
    from analytics_service.card_materializer import materialize_card_game_stats

    session = _FakeSession(
        queue=[
            # hero_player_name lookup
            [("alice",)],
            # games query -> empty
            [],
        ]
    )
    await materialize_card_game_stats(session, "test-match-id", user_id=1)
    assert len(session.execute_calls) == 2


@pytest.mark.asyncio
async def test_materialize_skips_when_no_events() -> None:
    """Materialization produces no rows when there are no game events."""
    from analytics_service.card_materializer import materialize_card_game_stats

    game_id = "game-uuid-1"
    session = _FakeSession(
        queue=[
            # hero_player_name
            [("alice",)],
            # games
            [(1, game_id)],
            # game_events -> empty
            [],
        ]
    )
    await materialize_card_game_stats(session, "test-match-id", user_id=1)
    assert len(session.execute_calls) == 3


@pytest.mark.asyncio
async def test_materialize_produces_correct_rows() -> None:
    """Full materialization with game events produces INSERT rows."""
    from analytics_service.card_materializer import materialize_card_game_stats

    match_id = "match-uuid-1"
    game_id = "game-uuid-1"

    session = _FakeSession(
        queue=[
            # hero_player_name
            [("alice",)],
            # games: (game_number, id)
            [(1, game_id)],
            # game_events: (game_id, turn_number, verb, card_name, player)
            [
                (game_id, 1, "cast", "Lightning Bolt", "alice"),
                (game_id, 2, "cast", "Lightning Bolt", "alice"),
                (game_id, 1, "play", "Mountain", "alice"),
                (game_id, 1, "cast", "Counterspell", "bob"),
            ],
            # oracle_id lookup: (name, oracle_id)
            [
                ("Lightning Bolt", "oracle-bolt-uuid"),
                ("Mountain", "oracle-mountain-uuid"),
                ("Counterspell", "oracle-counter-uuid"),
            ],
            # game_players: (game_id, player_name, is_local)
            [
                (game_id, "alice", True),
                (game_id, "bob", False),
            ],
            # game winners: (id, game_number, winner)
            [(game_id, 1, "alice")],
            # DELETE existing rows
            [],
        ]
    )

    await materialize_card_game_stats(session, match_id, user_id=1)

    # Count INSERT calls: should be 3 (Bolt for alice, Mountain for alice,
    # Counterspell for bob)
    insert_calls = [
        c for c in session.execute_calls if "INSERT INTO analytics.card_game_stats" in c["stmt"]
    ]
    assert len(insert_calls) == 3

    # Check the Lightning Bolt row for alice
    bolt_inserts = [c for c in insert_calls if c["params"]["card_name"] == "Lightning Bolt"]
    assert len(bolt_inserts) == 1
    bolt = bolt_inserts[0]["params"]
    assert bolt["is_local"] is True
    assert bolt["seen"] == 2
    assert bolt["cast"] == 2
    assert bolt["played"] == 0
    assert bolt["won"] is True  # alice won, alice is hero (is_local=True)
    assert bolt["first_cast_turn"] == 1
    assert bolt["oracle_id"] == "oracle-bolt-uuid"

    # Check the Mountain row for alice
    mountain_inserts = [c for c in insert_calls if c["params"]["card_name"] == "Mountain"]
    assert len(mountain_inserts) == 1
    mountain = mountain_inserts[0]["params"]
    assert mountain["is_local"] is True
    assert mountain["seen"] == 1
    assert mountain["cast"] == 0
    assert mountain["played"] == 1
    assert mountain["first_cast_turn"] is None  # never cast

    # Check the Counterspell row for bob
    counter_inserts = [c for c in insert_calls if c["params"]["card_name"] == "Counterspell"]
    assert len(counter_inserts) == 1
    counter = counter_inserts[0]["params"]
    assert counter["is_local"] is False
    assert counter["won"] is True  # alice (hero) won, from hero perspective


@pytest.mark.asyncio
async def test_materialize_postboard_flag() -> None:
    """Games after game 1 get is_postboard=True."""
    from analytics_service.card_materializer import materialize_card_game_stats

    match_id = "match-uuid-1"
    game1_id = "game-uuid-1"
    game2_id = "game-uuid-2"

    session = _FakeSession(
        queue=[
            # hero_player_name
            [("alice",)],
            # games: (game_number, id)
            [(1, game1_id), (2, game2_id)],
            # game_events
            [
                (game1_id, 1, "cast", "Bolt", "alice"),
                (game2_id, 1, "cast", "Bolt", "alice"),
            ],
            # oracle lookup
            [],
            # game_players
            [
                (game1_id, "alice", True),
                (game2_id, "alice", True),
            ],
            # game winners
            [(game1_id, 1, "alice"), (game2_id, 2, "bob")],
            # DELETE
            [],
        ]
    )

    await materialize_card_game_stats(session, match_id, user_id=1)

    insert_calls = [
        c for c in session.execute_calls if "INSERT INTO analytics.card_game_stats" in c["stmt"]
    ]
    assert len(insert_calls) == 2

    # Find game 1 and game 2 inserts
    g1_insert = [c for c in insert_calls if c["params"]["game_id"] == game1_id]
    g2_insert = [c for c in insert_calls if c["params"]["game_id"] == game2_id]
    assert len(g1_insert) == 1
    assert len(g2_insert) == 1

    assert g1_insert[0]["params"]["is_postboard"] is False
    assert g2_insert[0]["params"]["is_postboard"] is True


# ---------------------------------------------------------------------------
# card_materializer_loop tests
# ---------------------------------------------------------------------------


class _FakePubSub:
    """Minimal fake Redis pubsub."""

    def __init__(self, messages: list[dict[str, Any]] | None = None) -> None:
        self._messages = messages or []
        self.subscribed_channels: list[str] = []

    async def subscribe(self, channel: str) -> None:
        self.subscribed_channels.append(channel)

    async def listen(self):
        for msg in self._messages:
            yield msg
        raise ConnectionError("Redis gone")


def _make_yielding_sleep_tracker() -> tuple[Any, list[float]]:
    """Return (fake_sleep_coro, recorded_values)."""
    recorded: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        recorded.append(seconds)
        await asyncio.sleep(0)

    return _fake_sleep, recorded


@pytest.mark.asyncio
async def test_materializer_loop_reconnects() -> None:
    """Loop should reconnect after a Redis disconnect."""
    from analytics_service.card_materializer import card_materializer_loop

    call_count = 0
    target_calls = 3

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        mock_redis.pubsub.return_value = _FakePubSub()
        return mock_redis

    fake_sleep, sleep_values = _make_yielding_sleep_tracker()

    mock_sm = MagicMock()

    with (
        patch("analytics_service.card_materializer.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.card_materializer._async_sleep", side_effect=fake_sleep),
    ):
        task = asyncio.create_task(card_materializer_loop("redis://fake", mock_sm))
        for _ in range(500):
            await asyncio.sleep(0)
            if call_count >= target_calls:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert call_count >= target_calls
    assert len(sleep_values) >= 2
    assert sleep_values[0] == 1.0
    assert sleep_values[1] == 2.0


@pytest.mark.asyncio
async def test_materializer_loop_processes_event() -> None:
    """Loop should call materialize_card_game_stats on match.parsed events."""
    from analytics_service.card_materializer import card_materializer_loop

    materialized_matches: list[str] = []

    async def fake_materialize(session: Any, match_id: str, user_id: int) -> None:
        materialized_matches.append(match_id)

    call_count = 0

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        if call_count == 1:
            msg = {
                "type": "message",
                "data": json.dumps({"match_id": "abc-123", "user_id": "7"}),
            }
            mock_redis.pubsub.return_value = _FakePubSub([msg])
        else:
            mock_redis.pubsub.return_value = _FakePubSub()
        return mock_redis

    fake_sleep, _ = _make_yielding_sleep_tracker()

    # Build a sessionmaker that yields a mock session
    mock_session = AsyncMock()

    class _SessionCtx:
        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, *exc):
            return False

    mock_sm = MagicMock()
    mock_sm.return_value = _SessionCtx()

    with (
        patch("analytics_service.card_materializer.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.card_materializer._async_sleep", side_effect=fake_sleep),
        patch(
            "analytics_service.card_materializer.materialize_card_game_stats",
            side_effect=fake_materialize,
        ),
    ):
        task = asyncio.create_task(card_materializer_loop("redis://fake", mock_sm))
        for _ in range(500):
            await asyncio.sleep(0)
            if materialized_matches:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert "abc-123" in materialized_matches


@pytest.mark.asyncio
async def test_materializer_loop_skips_incomplete_payload() -> None:
    """Events missing match_id or user_id should be skipped."""
    from analytics_service.card_materializer import card_materializer_loop

    materialized_matches: list[str] = []

    async def fake_materialize(session: Any, match_id: str, user_id: int) -> None:
        materialized_matches.append(match_id)

    call_count = 0

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        if call_count == 1:
            # Missing user_id
            msg1 = {
                "type": "message",
                "data": json.dumps({"match_id": "abc-123"}),
            }
            # Missing match_id
            msg2 = {
                "type": "message",
                "data": json.dumps({"user_id": "7"}),
            }
            mock_redis.pubsub.return_value = _FakePubSub([msg1, msg2])
        else:
            mock_redis.pubsub.return_value = _FakePubSub()
        return mock_redis

    fake_sleep, _ = _make_yielding_sleep_tracker()
    mock_sm = MagicMock()

    with (
        patch("analytics_service.card_materializer.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.card_materializer._async_sleep", side_effect=fake_sleep),
        patch(
            "analytics_service.card_materializer.materialize_card_game_stats",
            side_effect=fake_materialize,
        ),
    ):
        task = asyncio.create_task(card_materializer_loop("redis://fake", mock_sm))
        # Give it time to process the messages + reconnect
        for _ in range(500):
            await asyncio.sleep(0)
            if call_count >= 2:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    # Neither message should have triggered materialization
    assert materialized_matches == []


@pytest.mark.asyncio
async def test_parser_no_longer_writes_card_game_stats() -> None:
    """Verify the parser consumer no longer references _materialize_card_game_stats."""
    import inspect

    from parser_service import consumer

    source = inspect.getsource(consumer)
    assert "_materialize_card_game_stats" not in source
    assert "analytics.card_game_stats" not in source
