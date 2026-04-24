"""Admin endpoint behavioral tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auth_service.models import AgentRegistration, User
from auth_service.models import Session as SessionRow
from auth_service.passwords import hash_password, verify_password
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


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_user_crud_happy_path(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)

    r = await client.post(
        "/admin/users",
        json={"email": "new@example.com", "password": "secretpw", "role": "user"},
        headers=_h(token),
    )
    assert r.status_code == 201, r.text
    new_user = r.json()
    assert new_user["email"] == "new@example.com"
    assert new_user["role"] == "user"
    assert new_user["must_change_password"] is True
    assert "password_hash" not in new_user
    new_id = new_user["id"]

    r = await client.get("/admin/users", headers=_h(token))
    assert r.status_code == 200
    emails = [u["email"] for u in r.json()["users"]]
    assert "new@example.com" in emails
    assert r.json()["total"] >= 2

    r = await client.patch(f"/admin/users/{new_id}", json={"role": "admin"}, headers=_h(token))
    assert r.status_code == 200
    assert r.json()["role"] == "admin"

    r = await client.delete(f"/admin/users/{new_id}", headers=_h(token))
    assert r.status_code == 204

    gone = (await db_session.execute(select(User).where(User.id == new_id))).scalar_one_or_none()
    assert gone is None


@pytest.mark.asyncio
async def test_create_user_email_conflict(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    payload = {"email": "dup@example.com", "password": "pw"}
    r1 = await client.post("/admin/users", json=payload, headers=_h(token))
    assert r1.status_code == 201
    r2 = await client.post("/admin/users", json=payload, headers=_h(token))
    assert r2.status_code == 409
    assert r2.json() == {"detail": {"error": "email_already_exists"}}
    # Case-insensitive collision check.
    r3 = await client.post(
        "/admin/users",
        json={"email": "DUP@example.com", "password": "pw"},
        headers=_h(token),
    )
    assert r3.status_code == 409


@pytest.mark.asyncio
async def test_update_requires_at_least_one_field(client: Any, db_session: AsyncSession) -> None:
    admin_id, token = await _seed_admin(client, db_session)
    r = await client.patch(f"/admin/users/{admin_id}", json={}, headers=_h(token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_cannot_demote_last_admin(client: Any, db_session: AsyncSession) -> None:
    admin_id, token = await _seed_admin(client, db_session)
    r = await client.patch(f"/admin/users/{admin_id}", json={"role": "user"}, headers=_h(token))
    assert r.status_code == 400
    assert r.json() == {"detail": {"error": "cannot_demote_last_admin"}}


@pytest.mark.asyncio
async def test_demote_allowed_when_multiple_admins(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.post(
        "/admin/users",
        json={"email": "a2@example.com", "password": "pw", "role": "admin"},
        headers=_h(token),
    )
    assert r.status_code == 201
    second_admin = r.json()["id"]
    r = await client.patch(f"/admin/users/{second_admin}", json={"role": "user"}, headers=_h(token))
    assert r.status_code == 200
    assert r.json()["role"] == "user"


@pytest.mark.asyncio
async def test_cannot_disable_self(client: Any, db_session: AsyncSession) -> None:
    admin_id, token = await _seed_admin(client, db_session)
    r = await client.patch(f"/admin/users/{admin_id}", json={"disabled": True}, headers=_h(token))
    assert r.status_code == 400
    assert r.json() == {"detail": {"error": "cannot_disable_self"}}


@pytest.mark.asyncio
async def test_cannot_delete_self(client: Any, db_session: AsyncSession) -> None:
    admin_id, token = await _seed_admin(client, db_session)
    r = await client.delete(f"/admin/users/{admin_id}", headers=_h(token))
    assert r.status_code == 400
    assert r.json() == {"detail": {"error": "cannot_delete_self"}}


@pytest.mark.asyncio
async def test_delete_admin_allowed_when_multiple(client: Any, db_session: AsyncSession) -> None:
    # With 2 active admins, deleting one is allowed (leaves the other).
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.post(
        "/admin/users",
        json={"email": "a2@example.com", "password": "pw", "role": "admin"},
        headers=_h(token),
    )
    assert r.status_code == 201
    a2_id = r.json()["id"]
    r = await client.delete(f"/admin/users/{a2_id}", headers=_h(token))
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_reset_password(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.post(
        "/admin/users",
        json={
            "email": "resetme@example.com",
            "password": "originalpw",
            "must_change_password": False,
        },
        headers=_h(token),
    )
    assert r.status_code == 201
    target_id = r.json()["id"]

    r = await client.post(f"/admin/users/{target_id}/reset-password", headers=_h(token))
    assert r.status_code == 200
    temp = r.json()["temporary_password"]
    assert isinstance(temp, str) and len(temp) >= 20

    await db_session.commit()  # release any locks
    fresh = (await db_session.execute(select(User).where(User.id == target_id))).scalar_one()
    await db_session.refresh(fresh)
    assert fresh.must_change_password is True
    assert verify_password(temp, fresh.password_hash)
    assert not verify_password("originalpw", fresh.password_hash)


@pytest.mark.asyncio
async def test_revoke_sessions(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    # Create a target user and log them in twice (two sessions).
    r = await client.post(
        "/admin/users",
        json={
            "email": "target@example.com",
            "password": "pw",
            "must_change_password": False,
        },
        headers=_h(token),
    )
    tid = r.json()["id"]
    await _login(client, "target@example.com", "pw")
    await _login(client, "target@example.com", "pw")

    r = await client.post(f"/admin/users/{tid}/revoke-sessions", headers=_h(token))
    assert r.status_code == 200
    assert r.json()["revoked_count"] == 2

    # Idempotent — no active sessions left.
    r = await client.post(f"/admin/users/{tid}/revoke-sessions", headers=_h(token))
    assert r.status_code == 200
    assert r.json()["revoked_count"] == 0


@pytest.mark.asyncio
async def test_agent_revoke_and_list(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)

    # Create a user + mint code + register an agent.
    r = await client.post(
        "/admin/users",
        json={
            "email": "agentowner@example.com",
            "password": "pw",
            "must_change_password": False,
        },
        headers=_h(token),
    )
    assert r.status_code == 201
    owner_token = await _login(client, "agentowner@example.com", "pw")
    r = await client.post("/auth/agent/registration-code", headers=_h(owner_token))
    assert r.status_code == 201
    code = r.json()["code"]
    r = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": "laptop-1", "client_version": "0.4.0"},
    )
    assert r.status_code == 201
    agent_id = r.json()["agent_id"]

    r = await client.get("/admin/agents", headers=_h(token))
    assert r.status_code == 200
    agents = r.json()["agents"]
    assert any(a["agent_id"] == agent_id for a in agents)
    agent_row = next(a for a in agents if a["agent_id"] == agent_id)
    assert agent_row["user_email"] == "agentowner@example.com"
    assert agent_row["revoked_at"] is None

    r = await client.post(f"/admin/agents/{agent_id}/revoke", headers=_h(token))
    assert r.status_code == 204
    # Idempotent.
    r = await client.post(f"/admin/agents/{agent_id}/revoke", headers=_h(token))
    assert r.status_code == 204

    r = await client.get("/admin/agents", headers=_h(token))
    agent_row = next(a for a in r.json()["agents"] if a["agent_id"] == agent_id)
    assert agent_row["revoked_at"] is not None


@pytest.mark.asyncio
async def test_cleanup_stale_agents(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)

    # Directly seed agents with varying last_seen_at values.
    owner = User(email="owner@example.com", password_hash=hash_password("pw"))
    db_session.add(owner)
    await db_session.commit()
    await db_session.refresh(owner)

    now = datetime.now(UTC)
    stale = AgentRegistration(
        user_id=owner.id,
        machine_name="stale",
        api_token_hash="h1",
        created_at=now - timedelta(days=120),
        last_seen_at=now - timedelta(days=100),
    )
    fresh = AgentRegistration(
        user_id=owner.id,
        machine_name="fresh",
        api_token_hash="h2",
        created_at=now - timedelta(days=10),
        last_seen_at=now - timedelta(days=5),
    )
    already_revoked = AgentRegistration(
        user_id=owner.id,
        machine_name="gone",
        api_token_hash="h3",
        created_at=now - timedelta(days=200),
        last_seen_at=now - timedelta(days=180),
        revoked_at=now - timedelta(days=150),
    )
    db_session.add_all([stale, fresh, already_revoked])
    await db_session.commit()
    await db_session.refresh(stale)
    await db_session.refresh(fresh)

    r = await client.post("/admin/agents/cleanup-stale?stale_days=90", headers=_h(token))
    assert r.status_code == 200
    body = r.json()
    assert body["revoked_count"] == 1
    assert "cutoff_date" in body

    await db_session.refresh(stale)
    await db_session.refresh(fresh)
    assert stale.revoked_at is not None
    assert fresh.revoked_at is None


@pytest.mark.asyncio
async def test_delete_user_cascades_sessions(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.post(
        "/admin/users",
        json={
            "email": "doomed@example.com",
            "password": "pw",
            "must_change_password": False,
        },
        headers=_h(token),
    )
    tid = r.json()["id"]
    await _login(client, "doomed@example.com", "pw")

    r = await client.delete(f"/admin/users/{tid}", headers=_h(token))
    assert r.status_code == 204

    sessions = (
        (await db_session.execute(select(SessionRow).where(SessionRow.user_id == tid)))
        .scalars()
        .all()
    )
    assert sessions == []


@pytest.mark.asyncio
async def test_agent_not_found_revoke(client: Any, db_session: AsyncSession) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.post(f"/admin/agents/{uuid.uuid4()}/revoke", headers=_h(token))
    assert r.status_code == 404
