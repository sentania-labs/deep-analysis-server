"""Tests for IP-based rate limiting on auth endpoints."""

from __future__ import annotations

from typing import Any

import pytest
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# /auth/login — 10 per minute per IP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_rate_limit_blocks_after_10(client: Any) -> None:
    """11th login attempt within 1 minute from the same IP returns 429."""
    payload = {"email": "nobody@example.com", "password": "wrong"}
    for _ in range(10):
        r = await client.post("/auth/login", json=payload)
        assert r.status_code in (200, 401), f"unexpected {r.status_code}"

    r = await client.post("/auth/login", json=payload)
    assert r.status_code == 429
    body = r.json()
    assert body["detail"]["detail"] == "rate_limit_exceeded"
    assert body["detail"]["retry_after_seconds"] > 0


@pytest.mark.asyncio
async def test_login_rate_limit_different_ips_independent(client: Any) -> None:
    """Requests from different IPs don't share rate-limit buckets."""
    payload = {"email": "nobody@example.com", "password": "wrong"}

    # Exhaust limit for IP-A.
    for _ in range(10):
        r = await client.post("/auth/login", json=payload, headers={"X-Forwarded-For": "1.2.3.4"})
        assert r.status_code in (200, 401)

    # IP-A is blocked.
    r = await client.post("/auth/login", json=payload, headers={"X-Forwarded-For": "1.2.3.4"})
    assert r.status_code == 429

    # IP-B still allowed.
    r = await client.post("/auth/login", json=payload, headers={"X-Forwarded-For": "5.6.7.8"})
    assert r.status_code in (200, 401)


@pytest.mark.asyncio
async def test_login_under_limit_succeeds(client: Any, db_session: AsyncSession) -> None:
    """A valid login under the rate limit returns 200, not 429."""
    u = User(email="rl-user@example.com", password_hash=hash_password("pw"))
    db_session.add(u)
    await db_session.commit()

    r = await client.post("/auth/login", json={"email": "rl-user@example.com", "password": "pw"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# /auth/register — 3 per hour per IP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_rate_limit_blocks_after_3(client: Any) -> None:
    """4th registration attempt within 1 hour returns 429."""
    for i in range(3):
        r = await client.post(
            "/auth/register",
            json={
                "email": f"reg-{i}@example.com",
                "password": "strong-password-123",
            },
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
        # Could be 201, 403 (invite required), etc. — not 429.
        assert r.status_code != 429, f"unexpected 429 on attempt {i + 1}"

    r = await client.post(
        "/auth/register",
        json={"email": "reg-extra@example.com", "password": "strong-password-123"},
        headers={"X-Forwarded-For": "10.0.0.1"},
    )
    assert r.status_code == 429
    body = r.json()
    assert body["detail"]["detail"] == "rate_limit_exceeded"
    assert body["detail"]["retry_after_seconds"] > 0


@pytest.mark.asyncio
async def test_register_different_ips_independent(client: Any) -> None:
    """Registration limits are per-IP — different IPs don't interfere."""
    for i in range(3):
        await client.post(
            "/auth/register",
            json={
                "email": f"regA-{i}@example.com",
                "password": "strong-password-123",
            },
            headers={"X-Forwarded-For": "10.0.0.2"},
        )

    # IP-A blocked.
    r = await client.post(
        "/auth/register",
        json={"email": "regA-extra@example.com", "password": "strong-password-123"},
        headers={"X-Forwarded-For": "10.0.0.2"},
    )
    assert r.status_code == 429

    # IP-B still fine.
    r = await client.post(
        "/auth/register",
        json={"email": "regB-0@example.com", "password": "strong-password-123"},
        headers={"X-Forwarded-For": "10.0.0.3"},
    )
    assert r.status_code != 429


# ---------------------------------------------------------------------------
# /auth/agent/register-with-credentials — 5 per minute per IP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_register_creds_rate_limit_blocks_after_5(client: Any) -> None:
    """6th agent registration attempt within 1 minute returns 429."""
    payload = {
        "email": "nobody@example.com",
        "password": "wrong",
        "agent_name": "test",
        "client_version": "0.0.1",
    }
    for _ in range(5):
        r = await client.post(
            "/auth/agent/register-with-credentials",
            json=payload,
            headers={"X-Forwarded-For": "192.168.1.1"},
        )
        assert r.status_code != 429

    r = await client.post(
        "/auth/agent/register-with-credentials",
        json=payload,
        headers={"X-Forwarded-For": "192.168.1.1"},
    )
    assert r.status_code == 429
    body = r.json()
    assert body["detail"]["detail"] == "rate_limit_exceeded"
    assert body["detail"]["retry_after_seconds"] > 0


@pytest.mark.asyncio
async def test_agent_register_creds_different_ips_independent(client: Any) -> None:
    """Agent-registration limits are per-IP."""
    payload = {
        "email": "nobody@example.com",
        "password": "wrong",
        "agent_name": "test",
        "client_version": "0.0.1",
    }

    # Exhaust IP-A.
    for _ in range(5):
        await client.post(
            "/auth/agent/register-with-credentials",
            json=payload,
            headers={"X-Forwarded-For": "192.168.1.2"},
        )

    # IP-A blocked.
    r = await client.post(
        "/auth/agent/register-with-credentials",
        json=payload,
        headers={"X-Forwarded-For": "192.168.1.2"},
    )
    assert r.status_code == 429

    # IP-B still allowed.
    r = await client.post(
        "/auth/agent/register-with-credentials",
        json=payload,
        headers={"X-Forwarded-For": "192.168.1.3"},
    )
    assert r.status_code != 429


# ---------------------------------------------------------------------------
# Unit test: RateLimiter directly
# ---------------------------------------------------------------------------


def test_rate_limiter_reset_clears_state() -> None:
    """``reset()`` wipes accumulated counters."""
    from auth_service.rate_limit import RateLimiter, RateLimitRule

    limiter = RateLimiter()
    rule = RateLimitRule(max_requests=1, window_seconds=60)
    limiter.check("test", "127.0.0.1", rule)

    # Second call should fail.
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        limiter.check("test", "127.0.0.1", rule)

    limiter.reset()
    # After reset, the first call should succeed again.
    limiter.check("test", "127.0.0.1", rule)
