"""POST /auth/agent/heartbeat tests."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from auth_service.models import AgentRegistration
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def _register_agent(
    client: Any, seed_user: dict[str, Any], machine_name: str = "laptop-1"
) -> dict[str, Any]:
    access = await _login(client, seed_user["email"], seed_user["password"])
    r = await client.post(
        "/auth/agent/registration-code",
        headers={"Authorization": f"Bearer {access}"},
    )
    code = r.json()["code"]
    r = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": machine_name, "client_version": "0.4.0"},
    )
    assert r.status_code == 201
    return dict(r.json())


@pytest.mark.asyncio
async def test_heartbeat_valid_token(
    client: Any, db_session: AsyncSession, seed_user: dict[str, Any]
) -> None:
    agent = await _register_agent(client, seed_user)
    before_row = (
        await db_session.execute(
            select(AgentRegistration).where(AgentRegistration.id == uuid.UUID(agent["agent_id"]))
        )
    ).scalar_one()
    before_seen = before_row.last_seen_at

    r = await client.post(
        "/auth/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent['api_token']}"},
        json={},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["revoked"] is False

    db_session.expire_all()
    after_row = (
        await db_session.execute(
            select(AgentRegistration).where(AgentRegistration.id == uuid.UUID(agent["agent_id"]))
        )
    ).scalar_one()
    assert after_row.last_seen_at is not None
    assert before_seen is None or after_row.last_seen_at >= before_seen


@pytest.mark.asyncio
async def test_heartbeat_unknown_token(client: Any) -> None:
    r = await client.post(
        "/auth/agent/heartbeat",
        headers={"Authorization": "Bearer not-a-real-token"},
        json={},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_heartbeat_updates_client_version(
    client: Any, db_session: AsyncSession, seed_user: dict[str, Any]
) -> None:
    agent = await _register_agent(client, seed_user)

    r = await client.post(
        "/auth/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent['api_token']}"},
        json={"client_version": "0.4.1"},
    )
    assert r.status_code == 200

    db_session.expire_all()
    row = (
        await db_session.execute(
            select(AgentRegistration).where(AgentRegistration.id == uuid.UUID(agent["agent_id"]))
        )
    ).scalar_one()
    assert row.client_version == "0.4.1"
