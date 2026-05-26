"""Tests for cache invalidation loop reconnect behaviour.

Verifies that ``_cache_invalidation_loop`` survives a Redis
disconnect and re-subscribes with exponential backoff rather
than exiting permanently.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys")
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


class _FakePubSub:
    """Minimal fake Redis pubsub that yields messages then raises.

    Always ends with a ``ConnectionError`` to simulate disconnect.
    The caller supplies zero or more messages to deliver first.
    """

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
    """Return (fake_sleep_coro, recorded_values).

    The fake sleep yields to the event loop (so the test can interleave
    with the task) but records the requested backoff value. Patched via
    ``analytics_service.main._async_sleep`` so ``asyncio.sleep`` itself
    is never touched and the event loop keeps working normally.
    """
    recorded: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        recorded.append(seconds)
        await asyncio.sleep(0)

    return _fake_sleep, recorded


@pytest.mark.asyncio
async def test_reconnects_after_disconnect() -> None:
    """Loop should reconnect after a Redis disconnect rather than exiting."""
    from analytics_service.main import _cache_invalidation_loop

    call_count = 0
    target_calls = 3

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        mock_redis.pubsub.return_value = _FakePubSub()
        return mock_redis

    fake_sleep, sleep_values = _make_yielding_sleep_tracker()

    with (
        patch("analytics_service.main.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.main._async_sleep", side_effect=fake_sleep),
    ):
        task = asyncio.create_task(_cache_invalidation_loop())
        for _ in range(500):
            await asyncio.sleep(0)
            if call_count >= target_calls:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert call_count >= target_calls, (
        f"Expected at least {target_calls} connections, got {call_count}"
    )
    # Verify exponential backoff sleeps
    assert len(sleep_values) >= 2
    assert sleep_values[0] == 1.0
    assert sleep_values[1] == 2.0


@pytest.mark.asyncio
async def test_processes_messages_after_reconnect() -> None:
    """After reconnecting, loop should process messages normally."""
    from analytics_service.main import _cache_invalidation_loop

    invalidated_users: list[int] = []
    call_count = 0

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        if call_count == 1:
            # First connection fails immediately (no messages)
            mock_redis.pubsub.return_value = _FakePubSub()
        else:
            # Second connection delivers a message then disconnects
            msg = {"type": "message", "data": json.dumps({"user_id": 42})}
            mock_redis.pubsub.return_value = _FakePubSub([msg])
        return mock_redis

    async def fake_invalidate(redis_client: Any, user_id: int) -> int:
        invalidated_users.append(user_id)
        return 1

    fake_sleep, _ = _make_yielding_sleep_tracker()

    with (
        patch("analytics_service.main.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.main.invalidate_user", side_effect=fake_invalidate),
        patch("analytics_service.main._async_sleep", side_effect=fake_sleep),
    ):
        task = asyncio.create_task(_cache_invalidation_loop())
        for _ in range(500):
            await asyncio.sleep(0)
            if invalidated_users:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert 42 in invalidated_users, f"Expected user 42 to be invalidated, got {invalidated_users}"


@pytest.mark.asyncio
async def test_backoff_caps_at_60s() -> None:
    """Backoff should not exceed 60 seconds."""
    from analytics_service.main import _cache_invalidation_loop

    call_count = 0
    target_calls = 8  # 1,2,4,8,16,32,60,60

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        mock_redis.pubsub.return_value = _FakePubSub()
        return mock_redis

    fake_sleep, sleep_values = _make_yielding_sleep_tracker()

    with (
        patch("analytics_service.main.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.main._async_sleep", side_effect=fake_sleep),
    ):
        task = asyncio.create_task(_cache_invalidation_loop())
        for _ in range(1000):
            await asyncio.sleep(0)
            if call_count >= target_calls:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert all(s <= 60.0 for s in sleep_values), f"Backoff exceeded 60s cap: {sleep_values}"
    assert len(sleep_values) >= 7, f"Expected at least 7 sleeps, got {len(sleep_values)}"
    # Sequence: 1, 2, 4, 8, 16, 32, 60, ...
    assert sleep_values[6] == 60.0


@pytest.mark.asyncio
async def test_backoff_resets_on_successful_message() -> None:
    """Receiving a message should reset backoff to 1s for subsequent failures."""
    from analytics_service.main import _cache_invalidation_loop

    call_count = 0

    async def fake_get_redis(url: str) -> MagicMock:
        nonlocal call_count
        call_count += 1
        mock_redis = MagicMock()
        if call_count <= 3:
            # First three connections fail immediately (no messages)
            mock_redis.pubsub.return_value = _FakePubSub()
        elif call_count == 4:
            # Fourth delivers a message before disconnecting — resets backoff
            msg = {"type": "message", "data": json.dumps({"user_id": 1})}
            mock_redis.pubsub.return_value = _FakePubSub([msg])
        else:
            # Fifth fails immediately — backoff should be 1s (was reset)
            mock_redis.pubsub.return_value = _FakePubSub()
        return mock_redis

    async def fake_invalidate(redis_client: Any, user_id: int) -> int:
        return 0

    fake_sleep, sleep_values = _make_yielding_sleep_tracker()

    with (
        patch("analytics_service.main.get_redis", side_effect=fake_get_redis),
        patch("analytics_service.main.invalidate_user", side_effect=fake_invalidate),
        patch("analytics_service.main._async_sleep", side_effect=fake_sleep),
    ):
        task = asyncio.create_task(_cache_invalidation_loop())
        for _ in range(1000):
            await asyncio.sleep(0)
            if call_count >= 6:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    # First three failures: 1, 2, 4
    # Fourth connection delivers a message (resetting backoff) then disconnects: 1
    # Fifth connection fails: 1 (backoff was reset)
    assert len(sleep_values) >= 5, f"Expected at least 5 sleeps, got {sleep_values}"
    assert sleep_values[0] == 1.0
    assert sleep_values[1] == 2.0
    assert sleep_values[2] == 4.0
    # After message on call 4, backoff resets, so the disconnect sleep is 1.0
    assert sleep_values[3] == 1.0, (
        f"Expected backoff reset to 1.0 after message, got {sleep_values[3]}"
    )
    # And the next failure (call 5) should also be 1.0 -> 2.0
    assert sleep_values[4] == 2.0, f"Expected 2.0 after reset+failure, got {sleep_values[4]}"
