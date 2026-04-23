"""POST /auth/login tests."""

from __future__ import annotations

from typing import Any

import pytest
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_unknown_email_returns_401(client: Any) -> None:
    r = await client.post("/auth/login", json={"email": "nope@example.com", "password": "whatever"})
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "invalid_credentials"}}


@pytest.mark.asyncio
async def test_wrong_password_returns_401(client: Any, db_session: AsyncSession) -> None:
    u = User(email="alice@example.com", password_hash=hash_password("right"))
    db_session.add(u)
    await db_session.commit()

    r = await client.post("/auth/login", json={"email": "alice@example.com", "password": "wrong"})
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "invalid_credentials"}}


@pytest.mark.asyncio
async def test_disabled_user_returns_401(client: Any, db_session: AsyncSession) -> None:
    u = User(
        email="bob@example.com",
        password_hash=hash_password("pw"),
        disabled=True,
    )
    db_session.add(u)
    await db_session.commit()

    r = await client.post("/auth/login", json={"email": "bob@example.com", "password": "pw"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_valid_login_creates_session(client: Any, db_session: AsyncSession) -> None:
    u = User(email="carol@example.com", password_hash=hash_password("pw"))
    db_session.add(u)
    await db_session.commit()
    await db_session.refresh(u)

    r = await client.post(
        "/auth/login",
        json={"email": "carol@example.com", "password": "pw"},
        headers={"user-agent": "pytest/1.0"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] == 900
    assert body["must_change_password"] is False

    sessions = (
        (await db_session.execute(select(SessionRow).where(SessionRow.user_id == u.id)))
        .scalars()
        .all()
    )
    assert len(sessions) == 1
    assert sessions[0].user_agent == "pytest/1.0"
    assert sessions[0].refresh_token_hash != body["refresh_token"]  # stored hashed


@pytest.mark.asyncio
async def test_must_change_password_propagates(client: Any, db_session: AsyncSession) -> None:
    u = User(
        email="dave@example.com",
        password_hash=hash_password("pw"),
        must_change_password=True,
    )
    db_session.add(u)
    await db_session.commit()

    r = await client.post("/auth/login", json={"email": "dave@example.com", "password": "pw"})
    assert r.status_code == 200
    assert r.json()["must_change_password"] is True


@pytest.mark.asyncio
async def test_email_lookup_is_case_insensitive(client: Any, db_session: AsyncSession) -> None:
    u = User(email="Eve@Example.com", password_hash=hash_password("pw"))
    db_session.add(u)
    await db_session.commit()

    r = await client.post("/auth/login", json={"email": "eve@example.com", "password": "pw"})
    assert r.status_code == 200
