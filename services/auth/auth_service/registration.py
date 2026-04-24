"""Agent registration code helpers.

Redis-backed short-lived codes (Option A). Trade-off: no audit trail,
but codes expire in 10 min and are atomic GETDEL (can't be
double-consumed). If Redis flushes, user just mints again. Simpler
than a registration_codes table for v0.4.0.
"""

from __future__ import annotations

import secrets

from redis.asyncio import Redis

from common.token_utils import hash_api_token as _shared_hash_api_token

# XXXX-XXXX, base32-ish without confusable chars (0/O, 1/I/L).
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 8  # 8 chars of 30-char alphabet ≈ 6.5e11 combinations


def generate_registration_code() -> str:
    """Return an 8-char alphanumeric code formatted XXXX-XXXX."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))
    return f"{raw[:4]}-{raw[4:]}"


async def store_registration_code(
    redis: Redis,
    code: str,
    user_id: int,
    ttl_seconds: int = 600,
) -> None:
    """Store code → user_id with the given TTL (default 10 min)."""
    await redis.set(f"regcode:{code}", str(user_id), ex=ttl_seconds)


async def consume_registration_code(redis: Redis, code: str) -> int | None:
    """Atomically read-and-delete the code, returning user_id or None.

    Uses Redis GETDEL so a code can only be consumed once — two agents
    racing the same code will see exactly one success.
    """
    raw = await redis.getdel(f"regcode:{code}")
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        return int(raw)
    except ValueError:
        return None


def generate_api_token() -> str:
    """Return a long-lived opaque bearer token (not a JWT)."""
    return secrets.token_urlsafe(32)


def hash_api_token(token: str) -> str:
    """SHA-256 hex; same shape as hash_refresh_token.

    Thin re-export of :func:`common.token_utils.hash_api_token` — kept
    here so existing ``auth_service.registration`` import sites don't
    need to change. The ingest service imports the common helper
    directly.
    """
    return _shared_hash_api_token(token)
