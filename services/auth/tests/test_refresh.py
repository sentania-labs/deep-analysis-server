"""POST /auth/refresh tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auth_service.jwt_issue import hash_refresh_token
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _login(client: Any, db_session: AsyncSession) -> dict[str, Any]:
    u = User(email="ref@example.com", password_hash=hash_password("pw"))
    db_session.add(u)
    await db_session.commit()
    r = await client.post("/auth/login", json={"email": "ref@example.com", "password": "pw"})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_valid_refresh_rotates_tokens(client: Any, db_session: AsyncSession) -> None:
    tokens = await _login(client, db_session)

    r = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200, r.text
    new = r.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert new["access_token"] != tokens["access_token"]

    # Old session revoked, new session exists.
    rows = (
        (await db_session.execute(select(SessionRow).order_by(SessionRow.issued_at.asc())))
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None


@pytest.mark.asyncio
async def test_revoked_session_refresh_returns_401(client: Any, db_session: AsyncSession) -> None:
    tokens = await _login(client, db_session)

    row = (
        await db_session.execute(
            select(SessionRow).where(
                SessionRow.refresh_token_hash == hash_refresh_token(tokens["refresh_token"])
            )
        )
    ).scalar_one()
    row.revoked_at = datetime.now(UTC)
    await db_session.commit()

    r = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_expired_session_refresh_returns_401(client: Any, db_session: AsyncSession) -> None:
    tokens = await _login(client, db_session)
    row = (
        await db_session.execute(
            select(SessionRow).where(
                SessionRow.refresh_token_hash == hash_refresh_token(tokens["refresh_token"])
            )
        )
    ).scalar_one()
    row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    r = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_old_refresh_token_unusable_after_rotation(
    client: Any, db_session: AsyncSession
) -> None:
    tokens = await _login(client, db_session)
    first = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert first.status_code == 200

    replay = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401
