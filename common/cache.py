"""Redis caching layer for analytics endpoints.

Provides a simple get/set interface with deterministic cache keys and
TTL-based expiry. Cache invalidation is pattern-based: when a
``match.parsed`` event fires, all keys for the affected user are
deleted via SCAN.

Cache key format: ``da:stats:{user_id}:{endpoint}:{params_hash}``
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import redis.asyncio as redis
from prometheus_client import Counter

_log = logging.getLogger("common.cache")

_DEFAULT_TTL = 300  # 5 minutes

# Prometheus counters (P2 cache metrics)
cache_hits_total = Counter(
    "da_cache_hits_total",
    "Total cache hits",
    labelnames=("endpoint",),
)
cache_misses_total = Counter(
    "da_cache_misses_total",
    "Total cache misses",
    labelnames=("endpoint",),
)


def cache_key(user_id: int, endpoint: str, **filters: Any) -> str:
    """Build a deterministic cache key from user + endpoint + filters.

    Filters are sorted by key name and hashed to keep the key short.
    """
    # Remove None values so absent filters don't affect the key
    clean = {k: v for k, v in sorted(filters.items()) if v is not None}
    if clean:
        raw = json.dumps(clean, sort_keys=True, default=str)
        params_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]
    else:
        params_hash = "nofilter"
    return f"da:stats:{user_id}:{endpoint}:{params_hash}"


async def get_cached(
    redis_client: redis.Redis,
    key: str,
    endpoint: str = "",
) -> dict[str, Any] | list[Any] | None:
    """Fetch a cached value. Returns None on miss or error."""
    try:
        raw = await redis_client.get(key)
    except Exception:  # noqa: BLE001
        _log.warning("cache get failed for key=%s", key, exc_info=True)
        cache_misses_total.labels(endpoint=endpoint).inc()
        return None
    if raw is None:
        cache_misses_total.labels(endpoint=endpoint).inc()
        return None
    try:
        cache_hits_total.labels(endpoint=endpoint).inc()
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        _log.warning("cache deserialization failed for key=%s", key)
        return None


async def set_cached(
    redis_client: redis.Redis,
    key: str,
    value: Any,
    ttl: int = _DEFAULT_TTL,
) -> None:
    """Store a value in cache with a TTL (seconds)."""
    try:
        raw = json.dumps(value, default=str)
        await redis_client.set(key, raw, ex=ttl)
    except Exception:  # noqa: BLE001
        _log.warning("cache set failed for key=%s", key, exc_info=True)


async def invalidate_user(redis_client: redis.Redis, user_id: int) -> int:
    """Delete all cache keys for a given user using SCAN.

    Returns the number of keys deleted.
    """
    pattern = f"da:stats:{user_id}:*"
    deleted = 0
    try:
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                await redis_client.delete(*keys)
                deleted += len(keys)
            if cursor == 0:
                break
    except Exception:  # noqa: BLE001
        _log.warning("cache invalidation failed for user_id=%s", user_id, exc_info=True)
    return deleted
