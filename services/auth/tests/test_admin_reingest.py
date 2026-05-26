"""Admin reingest endpoint tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from auth_service.models import AgentRegistration, User
from auth_service.passwords import hash_password
from auth_service.registration import generate_api_token, hash_api_token
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def _seed_admin(
    client: Any, db: AsyncSession, email: str = "admin@example.com", password: str = "pw"
) -> tuple[int, str]:
    u = User(email=email, password_hash=hash_password(password), role="admin")
    db.add(u)
    await db.commit()
    await db.refresh(u)
    token = await _login(client, email, password)
    return u.id, token


async def _seed_user(db: AsyncSession, email: str = "player@example.com") -> int:
    u = User(email=email, password_hash=hash_password("pw"), role="user")
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u.id


async def _seed_agent(
    db: AsyncSession, user_id: int, *, machine_name: str = "pc-1", revoked: bool = False
) -> tuple[uuid.UUID, str]:
    token = generate_api_token()
    agent = AgentRegistration(
        user_id=user_id,
        machine_name=machine_name,
        api_token_hash=hash_api_token(token),
        created_at=datetime.now(UTC),
        last_seen_at=datetime.now(UTC),
        client_version="0.5.0",
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent.id, token


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# -----------------------------------------------------------------------
# POST /admin/agents/{agent_id}/reingest
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reingest_single_agent(client: Any, db_session: AsyncSession) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    user_id = await _seed_user(db_session)
    agent_id, _ = await _seed_agent(db_session, user_id)

    r = await client.post(f"/admin/agents/{agent_id}/reingest", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["affected_count"] == 1

    db_session.expire_all()
    row = (
        await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == agent_id))
    ).scalar_one()
    assert row.reingest_requested_at is not None


@pytest.mark.asyncio
async def test_reingest_single_agent_revoked_is_skipped(
    client: Any, db_session: AsyncSession
) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    user_id = await _seed_user(db_session)
    agent_id, _ = await _seed_agent(db_session, user_id, revoked=True)

    r = await client.post(f"/admin/agents/{agent_id}/reingest", headers=_h(admin_token))
    assert r.status_code == 200
    assert r.json()["affected_count"] == 0

    db_session.expire_all()
    row = (
        await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == agent_id))
    ).scalar_one()
    assert row.reingest_requested_at is None


@pytest.mark.asyncio
async def test_reingest_single_agent_not_found(client: Any, db_session: AsyncSession) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    fake_id = uuid.uuid4()
    r = await client.post(f"/admin/agents/{fake_id}/reingest", headers=_h(admin_token))
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "agent_not_found"


# -----------------------------------------------------------------------
# POST /admin/users/{user_id}/reingest
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reingest_user_agents(client: Any, db_session: AsyncSession) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    user_id = await _seed_user(db_session)
    a1_id, _ = await _seed_agent(db_session, user_id, machine_name="pc-1")
    a2_id, _ = await _seed_agent(db_session, user_id, machine_name="pc-2")
    # Add a revoked agent that should be skipped
    a3_id, _ = await _seed_agent(db_session, user_id, machine_name="pc-3", revoked=True)

    r = await client.post(f"/admin/users/{user_id}/reingest", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["affected_count"] == 2

    db_session.expire_all()
    for aid in (a1_id, a2_id):
        row = (
            await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == aid))
        ).scalar_one()
        assert row.reingest_requested_at is not None

    # Revoked agent should not have reingest_requested_at set
    revoked_row = (
        await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == a3_id))
    ).scalar_one()
    assert revoked_row.reingest_requested_at is None


@pytest.mark.asyncio
async def test_reingest_user_not_found(client: Any, db_session: AsyncSession) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    r = await client.post("/admin/users/99999/reingest", headers=_h(admin_token))
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "user_not_found"


# -----------------------------------------------------------------------
# POST /admin/agents/reingest-all
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reingest_all_agents(client: Any, db_session: AsyncSession) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    u1_id = await _seed_user(db_session, email="u1@example.com")
    u2_id = await _seed_user(db_session, email="u2@example.com")
    a1_id, _ = await _seed_agent(db_session, u1_id, machine_name="pc-1")
    a2_id, _ = await _seed_agent(db_session, u2_id, machine_name="pc-2")
    a3_id, _ = await _seed_agent(db_session, u2_id, machine_name="pc-3", revoked=True)

    r = await client.post("/admin/agents/reingest-all", headers=_h(admin_token))
    assert r.status_code == 200
    assert r.json()["affected_count"] == 2

    db_session.expire_all()
    for aid in (a1_id, a2_id):
        row = (
            await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == aid))
        ).scalar_one()
        assert row.reingest_requested_at is not None

    revoked_row = (
        await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == a3_id))
    ).scalar_one()
    assert revoked_row.reingest_requested_at is None


# -----------------------------------------------------------------------
# Heartbeat includes reingest_requested_at
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_heartbeat_includes_reingest_requested_at(
    client: Any, db_session: AsyncSession
) -> None:
    _, admin_token = await _seed_admin(client, db_session)
    user_id = await _seed_user(db_session)
    agent_id, agent_token = await _seed_agent(db_session, user_id)

    # Heartbeat before reingest — should be null
    r = await client.post(
        "/auth/agent/heartbeat",
        headers=_h(agent_token),
        json={},
    )
    assert r.status_code == 200
    assert r.json()["reingest_requested_at"] is None

    # Admin triggers reingest
    r = await client.post(f"/admin/agents/{agent_id}/reingest", headers=_h(admin_token))
    assert r.status_code == 200

    # Heartbeat after reingest — should have a timestamp
    r = await client.post(
        "/auth/agent/heartbeat",
        headers=_h(agent_token),
        json={},
    )
    assert r.status_code == 200
    assert r.json()["reingest_requested_at"] is not None


# -----------------------------------------------------------------------
# Self-service: POST /auth/agent/reingest
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_self_service_reingest(client: Any, db_session: AsyncSession) -> None:
    user_id = await _seed_user(db_session)
    agent_id, agent_token = await _seed_agent(db_session, user_id)

    r = await client.post("/auth/agent/reingest", headers=_h(agent_token))
    assert r.status_code == 200
    assert r.json()["affected_count"] == 1

    db_session.expire_all()
    row = (
        await db_session.execute(select(AgentRegistration).where(AgentRegistration.id == agent_id))
    ).scalar_one()
    assert row.reingest_requested_at is not None


@pytest.mark.asyncio
async def test_self_service_reingest_rate_limited(client: Any, db_session: AsyncSession) -> None:
    user_id = await _seed_user(db_session)
    _agent_id, agent_token = await _seed_agent(db_session, user_id)

    # First call succeeds
    r = await client.post("/auth/agent/reingest", headers=_h(agent_token))
    assert r.status_code == 200

    # Second call within 1 hour is rate-limited
    r = await client.post("/auth/agent/reingest", headers=_h(agent_token))
    assert r.status_code == 429
    body = r.json()
    assert body["detail"]["error"] == "rate_limited"
    assert "retry_after_seconds" in body["detail"]


@pytest.mark.asyncio
async def test_self_service_reingest_revoked_agent(client: Any, db_session: AsyncSession) -> None:
    user_id = await _seed_user(db_session)
    _agent_id, agent_token = await _seed_agent(db_session, user_id, revoked=True)

    r = await client.post("/auth/agent/reingest", headers=_h(agent_token))
    assert r.status_code == 401


# -----------------------------------------------------------------------
# Auth gate — non-admin is rejected
# -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reingest_requires_admin(client: Any, db_session: AsyncSession) -> None:
    user_id = await _seed_user(db_session)
    user_token = await _login(client, "player@example.com", "pw")
    agent_id, _ = await _seed_agent(db_session, user_id)

    r = await client.post(f"/admin/agents/{agent_id}/reingest", headers=_h(user_token))
    assert r.status_code in (401, 403)

    r = await client.post(f"/admin/users/{user_id}/reingest", headers=_h(user_token))
    assert r.status_code in (401, 403)

    r = await client.post("/admin/agents/reingest-all", headers=_h(user_token))
    assert r.status_code in (401, 403)
