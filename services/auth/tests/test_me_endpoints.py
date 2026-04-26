"""Self-service /auth/me endpoint behavioral tests.

Covers the W3.5-B surface: per-user agent listing, profile email
update, and per-user agent revoke. The admin variants are covered
separately in test_admin_endpoints.py.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def _seed_user(
    db: AsyncSession,
    email: str = "owner@example.com",
    password: str = "pw",
    role: str = "user",
) -> int:
    u = User(email=email, password_hash=hash_password(password), role=role)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return int(u.id)


async def _register_agent(
    client: Any,
    user_token: str,
    machine_name: str = "laptop-1",
    client_version: str = "0.4.0",
) -> str:
    r = await client.post("/auth/agent/registration-code", headers=_h(user_token))
    assert r.status_code == 201, r.text
    code = r.json()["code"]
    r = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": machine_name, "client_version": client_version},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["agent_id"])


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /auth/me/agents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_agents_returns_only_callers_agents(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="owner@example.com", password="pw")
    await _seed_user(db_session, email="other@example.com", password="pw")
    owner_token = await _login(client, "owner@example.com", "pw")
    other_token = await _login(client, "other@example.com", "pw")

    owner_agent = await _register_agent(client, owner_token, machine_name="owner-laptop")
    other_agent = await _register_agent(client, other_token, machine_name="other-laptop")

    r = await client.get("/auth/me/agents", headers=_h(owner_token))
    assert r.status_code == 200, r.text
    body = r.json()
    ids = [a["agent_id"] for a in body["agents"]]
    assert owner_agent in ids
    assert other_agent not in ids
    assert body["total"] == 1


@pytest.mark.asyncio
async def test_me_agents_requires_auth(client: Any) -> None:
    r = await client.get("/auth/me/agents")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_me_agents_pagination(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="owner@example.com", password="pw")
    token = await _login(client, "owner@example.com", "pw")
    for i in range(3):
        await _register_agent(client, token, machine_name=f"box-{i}")

    r = await client.get("/auth/me/agents?limit=2&offset=0", headers=_h(token))
    assert r.status_code == 200
    body = r.json()
    assert len(body["agents"]) == 2
    assert body["total"] == 3


# ---------------------------------------------------------------------------
# PATCH /auth/me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_me_updates_email(client: Any, db_session: AsyncSession) -> None:
    user_id = await _seed_user(db_session, email="orig@example.com", password="pw")
    token = await _login(client, "orig@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": "renamed@example.com"}, headers=_h(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email"] == "renamed@example.com"
    assert body["user_id"] == user_id

    fresh = (await db_session.execute(select(User).where(User.id == user_id))).scalar_one()
    await db_session.refresh(fresh)
    assert fresh.email == "renamed@example.com"


@pytest.mark.asyncio
async def test_patch_me_normalizes_lowercase(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="orig@example.com", password="pw")
    token = await _login(client, "orig@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": "Renamed@Example.COM"}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "renamed@example.com"


@pytest.mark.asyncio
async def test_patch_me_email_conflict(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="taken@example.com", password="pw")
    await _seed_user(db_session, email="orig@example.com", password="pw")
    token = await _login(client, "orig@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": "taken@example.com"}, headers=_h(token))
    assert r.status_code == 409
    assert r.json() == {"detail": {"error": "email_already_exists"}}


@pytest.mark.asyncio
async def test_patch_me_email_conflict_case_insensitive(
    client: Any, db_session: AsyncSession
) -> None:
    await _seed_user(db_session, email="taken@example.com", password="pw")
    await _seed_user(db_session, email="orig@example.com", password="pw")
    token = await _login(client, "orig@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": "TAKEN@example.com"}, headers=_h(token))
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_patch_me_same_email_is_idempotent(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="orig@example.com", password="pw")
    token = await _login(client, "orig@example.com", "pw")

    # Setting your own current email isn't a conflict.
    r = await client.patch("/auth/me", json={"email": "orig@example.com"}, headers=_h(token))
    assert r.status_code == 200
    assert r.json()["email"] == "orig@example.com"


@pytest.mark.asyncio
async def test_patch_me_rejects_empty_email(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="orig@example.com", password="pw")
    token = await _login(client, "orig@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": ""}, headers=_h(token))
    assert r.status_code == 422  # Pydantic min_length validation


@pytest.mark.asyncio
async def test_patch_me_requires_auth(client: Any) -> None:
    r = await client.patch("/auth/me", json={"email": "x@example.com"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/me/agents/{agent_id}/revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_revoke_own_agent(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="owner@example.com", password="pw")
    token = await _login(client, "owner@example.com", "pw")
    agent_id = await _register_agent(client, token)

    r = await client.post(f"/auth/me/agents/{agent_id}/revoke", headers=_h(token))
    assert r.status_code == 204

    # Idempotent — second revoke also returns 204.
    r = await client.post(f"/auth/me/agents/{agent_id}/revoke", headers=_h(token))
    assert r.status_code == 204

    # Listing now shows the agent as revoked.
    r = await client.get("/auth/me/agents", headers=_h(token))
    row = next(a for a in r.json()["agents"] if a["agent_id"] == agent_id)
    assert row["revoked_at"] is not None


@pytest.mark.asyncio
async def test_me_revoke_someone_elses_agent_404(client: Any, db_session: AsyncSession) -> None:
    # Non-owners get 404 (not 403) so we don't leak the existence of
    # other users' agent IDs through an enumeration probe.
    await _seed_user(db_session, email="owner@example.com", password="pw")
    await _seed_user(db_session, email="other@example.com", password="pw")
    owner_token = await _login(client, "owner@example.com", "pw")
    other_token = await _login(client, "other@example.com", "pw")
    other_agent = await _register_agent(client, other_token, machine_name="other-laptop")

    r = await client.post(f"/auth/me/agents/{other_agent}/revoke", headers=_h(owner_token))
    assert r.status_code == 404
    assert r.json() == {"detail": {"error": "agent_not_found"}}


@pytest.mark.asyncio
async def test_me_revoke_unknown_agent_404(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="owner@example.com", password="pw")
    token = await _login(client, "owner@example.com", "pw")

    r = await client.post(f"/auth/me/agents/{uuid.uuid4()}/revoke", headers=_h(token))
    assert r.status_code == 404
    assert r.json() == {"detail": {"error": "agent_not_found"}}


@pytest.mark.asyncio
async def test_me_revoke_requires_auth(client: Any) -> None:
    r = await client.post(f"/auth/me/agents/{uuid.uuid4()}/revoke")
    assert r.status_code == 401
