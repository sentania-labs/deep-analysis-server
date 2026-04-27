"""POST /auth/agent/register tests."""

from __future__ import annotations

from typing import Any

import pytest


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def _mint_code(client: Any, access_token: str) -> str:
    r = await client.post(
        "/auth/agent/registration-code",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 201
    return str(r.json()["code"])


@pytest.mark.asyncio
async def test_register_valid_code(client: Any, seed_user: dict[str, Any]) -> None:
    access = await _login(client, seed_user["email"], seed_user["password"])
    code = await _mint_code(client, access)

    r = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": "laptop-1", "client_version": "0.4.0"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["agent_id"]
    assert body["api_token"]
    assert body["user_id"] == seed_user["id"]


@pytest.mark.asyncio
async def test_register_same_code_twice(client: Any, seed_user: dict[str, Any]) -> None:
    access = await _login(client, seed_user["email"], seed_user["password"])
    code = await _mint_code(client, access)

    r1 = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": "laptop-1", "client_version": "0.4.0"},
    )
    assert r1.status_code == 201

    r2 = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": "laptop-2", "client_version": "0.4.0"},
    )
    assert r2.status_code == 401
    assert r2.json() == {"detail": {"error": "invalid_registration_code"}}


@pytest.mark.asyncio
async def test_register_invalid_code(client: Any) -> None:
    r = await client.post(
        "/auth/agent/register",
        json={"code": "BOGU-SCOD", "machine_name": "laptop-1", "client_version": "0.4.0"},
    )
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "invalid_registration_code"}}


@pytest.mark.asyncio
async def test_register_rejects_admin_owned_code(
    client: Any,
    redis_client: Any,
    db_session: Any,
) -> None:
    """A registration code minted by (or for) a user whose role is now
    'admin' must be refused at consume time, even if it is still valid
    in Redis. Defends against pre-W3.6.1 codes carrying through the
    role split."""
    from auth_service.models import User
    from auth_service.passwords import hash_password
    from auth_service.registration import (
        generate_registration_code,
        store_registration_code,
    )

    admin = User(
        email="admin-stale-code@example.com",
        password_hash=hash_password("BootstrapPw2026!"),
        role="admin",
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)

    code = generate_registration_code()
    await store_registration_code(redis_client, code, admin.id, ttl_seconds=600)

    r = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": "laptop-1", "client_version": "0.4.0"},
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "admin_cannot_register_agent"}}
