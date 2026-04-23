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
