"""POST /auth/logout tests."""

from __future__ import annotations

from typing import Any

import pytest
from auth_service.jwt_issue import hash_refresh_token
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _login(client: Any, db_session: AsyncSession) -> dict[str, Any]:
    u = User(email="logout@example.com", password_hash=hash_password("pw"))
    db_session.add(u)
    await db_session.commit()
    r = await client.post("/auth/login", json={"email": "logout@example.com", "password": "pw"})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_logout_marks_session_revoked(client: Any, db_session: AsyncSession) -> None:
    tokens = await _login(client, db_session)

    r = await client.post(
        "/auth/logout",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 204

    row = (
        await db_session.execute(
            select(SessionRow).where(
                SessionRow.refresh_token_hash == hash_refresh_token(tokens["refresh_token"])
            )
        )
    ).scalar_one()
    assert row.revoked_at is not None


@pytest.mark.asyncio
async def test_second_logout_is_idempotent(client: Any, db_session: AsyncSession) -> None:
    tokens = await _login(client, db_session)
    headers = {"authorization": f"Bearer {tokens['access_token']}"}

    r1 = await client.post("/auth/logout", headers=headers)
    r2 = await client.post("/auth/logout", headers=headers)
    assert r1.status_code == 204
    assert r2.status_code == 204


@pytest.mark.asyncio
async def test_post_logout_refresh_returns_401(client: Any, db_session: AsyncSession) -> None:
    tokens = await _login(client, db_session)

    await client.post(
        "/auth/logout",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    r = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_missing_token_still_204(client: Any) -> None:
    r = await client.post("/auth/logout")
    assert r.status_code == 204
