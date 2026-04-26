"""Hard role separation: admins cannot use self-service mutations.

W3.6 sub-item 1 — admin is purely administrative. The /auth/me/agents
mutation routes and the /auth/agent/registration-code mint endpoint
return 403 ``admin_self_service_disabled`` for admin callers. Read
endpoints (GET /auth/me, GET /auth/me/agents) remain available so the
admin panel and self-introspection still work.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy.ext.asyncio import AsyncSession


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def _seed(
    db: AsyncSession,
    *,
    email: str,
    role: str,
    password: str = "pw",
) -> int:
    u = User(email=email, password_hash=hash_password(password), role=role)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return int(u.id)


# ---------------------------------------------------------------------------
# PATCH /auth/me — admins blocked, users allowed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_me_admin_403(client: Any, db_session: AsyncSession) -> None:
    await _seed(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": "renamed@example.com"}, headers=_h(token))
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "admin_self_service_disabled"}}


@pytest.mark.asyncio
async def test_patch_me_user_200(client: Any, db_session: AsyncSession) -> None:
    await _seed(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.patch("/auth/me", json={"email": "renamed@example.com"}, headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "renamed@example.com"


# ---------------------------------------------------------------------------
# POST /auth/me/agents/{id}/revoke — admins blocked, users allowed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_my_agent_admin_403(client: Any, db_session: AsyncSession) -> None:
    await _seed(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.post(f"/auth/me/agents/{uuid.uuid4()}/revoke", headers=_h(token))
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "admin_self_service_disabled"}}


@pytest.mark.asyncio
async def test_revoke_my_agent_user_404_for_unknown(client: Any, db_session: AsyncSession) -> None:
    # User without a matching agent gets the normal 404 — not the new
    # 403. Confirms the role gate runs before the lookup.
    await _seed(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.post(f"/auth/me/agents/{uuid.uuid4()}/revoke", headers=_h(token))
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /auth/agent/registration-code — admins blocked, users allowed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mint_registration_code_admin_403(client: Any, db_session: AsyncSession) -> None:
    await _seed(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.post("/auth/agent/registration-code", headers=_h(token))
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "admin_self_service_disabled"}}


@pytest.mark.asyncio
async def test_mint_registration_code_user_201(client: Any, db_session: AsyncSession) -> None:
    await _seed(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.post("/auth/agent/registration-code", headers=_h(token))
    assert r.status_code == 201, r.text
    assert "code" in r.json()


# ---------------------------------------------------------------------------
# Read endpoints stay available to admins.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_me_admin_still_200(client: Any, db_session: AsyncSession) -> None:
    await _seed(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.get("/auth/me", headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"


@pytest.mark.asyncio
async def test_list_my_agents_admin_still_200(client: Any, db_session: AsyncSession) -> None:
    # GET /auth/me/agents stays open to admins (returns an empty list,
    # since admins cannot own agents post-W3.6). Read access is still
    # the right behavior for admin-side introspection.
    await _seed(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.get("/auth/me/agents", headers=_h(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 0
    assert body["agents"] == []
