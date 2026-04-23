"""Async Redis factory and event publisher."""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as redis

_CLIENTS: dict[str, redis.Redis] = {}


async def get_redis(url: str) -> redis.Redis:
    """Return a pooled async Redis client for the given URL. Singleton per URL."""
    if url not in _CLIENTS:
        _CLIENTS[url] = redis.from_url(url, decode_responses=True)
    return _CLIENTS[url]


class EventPublisher:
    def __init__(self, redis_client: redis.Redis) -> None:
        self._redis = redis_client

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        await self._redis.publish(topic, json.dumps(payload))
