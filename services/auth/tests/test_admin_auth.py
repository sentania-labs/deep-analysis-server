"""Admin-claim gate tests — GET /admin/users as representative endpoint."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from auth_service.jwt_issue import JWTIssuer
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _seed_user_with_login(
    client: Any, db: AsyncSession, role: str, email: str, password: str = "pw"
) -> str:
    u = User(email=email, password_hash=hash_password(password), role=role)
    db.add(u)
    await db.commit()

    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


@pytest.mark.asyncio
async def test_missing_token_returns_401(client: Any) -> None:
    r = await client.get("/admin/users")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_user_role_token_returns_403(client: Any, db_session: AsyncSession) -> None:
    token = await _seed_user_with_login(client, db_session, "user", "u1@example.com")
    r = await client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "forbidden"}}


@pytest.mark.asyncio
async def test_admin_role_token_returns_200(client: Any, db_session: AsyncSession) -> None:
    token = await _seed_user_with_login(client, db_session, "admin", "a1@example.com")
    r = await client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert "users" in body and "total" in body


@pytest.mark.asyncio
async def test_expired_admin_token_returns_401(client: Any, db_session: AsyncSession) -> None:
    # Log in to establish a real session, then craft an expired JWT with the same sid.
    token = await _seed_user_with_login(client, db_session, "admin", "a2@example.com")
    assert token
    u = (await db_session.execute(select(User).where(User.email == "a2@example.com"))).scalar_one()
    session_row = (
        await db_session.execute(select(SessionRow).where(SessionRow.user_id == u.id))
    ).scalar_one()

    expired_issuer = JWTIssuer(
        private_key_path=Path(os.environ["DA_JWT_PRIVATE_KEY_PATH"]),
        issuer="deep-analysis-auth",
        audience="deep-analysis",
        access_ttl_seconds=-60,
    )
    expired = expired_issuer.issue_access_token(u.id, "admin", session_row.id)

    r = await client.get("/admin/users", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_malformed_auth_header_returns_401(client: Any) -> None:
    r = await client.get("/admin/users", headers={"Authorization": "NotBearer x"})
    assert r.status_code == 401
    r = await client.get("/admin/users", headers={"Authorization": "Bearer "})
    assert r.status_code == 401
    r = await client.get("/admin/users", headers={"Authorization": f"Bearer {uuid.uuid4()}"})
    assert r.status_code == 401
