"""POST /auth/agent/register-with-credentials tests.

One-step agent registration: authenticate via email+password and
return {agent_id, api_token, user_id} in a single call. Lets agents
ship a username/password registration UX without a separate code
copy-paste step.
"""

from __future__ import annotations

from typing import Any

import pytest
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_register_with_credentials_success(client: Any, seed_user: dict[str, Any]) -> None:
    r = await client.post(
        "/auth/agent/register-with-credentials",
        json={
            "email": seed_user["email"],
            "password": seed_user["password"],
            "agent_name": "laptop-1",
            "client_version": "0.7.12",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["agent_id"]
    assert body["api_token"]
    assert body["user_id"] == seed_user["id"]


@pytest.mark.asyncio
async def test_register_with_credentials_wrong_password(
    client: Any, seed_user: dict[str, Any]
) -> None:
    r = await client.post(
        "/auth/agent/register-with-credentials",
        json={
            "email": seed_user["email"],
            "password": "definitely-not-the-password",
            "agent_name": "laptop-1",
            "client_version": "0.7.12",
        },
    )
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "invalid_credentials"}}


@pytest.mark.asyncio
async def test_register_with_credentials_unknown_email(client: Any) -> None:
    r = await client.post(
        "/auth/agent/register-with-credentials",
        json={
            "email": "nobody@example.com",
            "password": "anything",
            "agent_name": "laptop-1",
            "client_version": "0.7.12",
        },
    )
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "invalid_credentials"}}


@pytest.mark.asyncio
async def test_register_with_credentials_rejects_admin(
    client: Any, db_session: AsyncSession
) -> None:
    """Mirrors the role guard on POST /auth/agent/register: admins
    can't own agents under the W3.6.1 hard role split."""
    admin = User(
        email="admin-cred-reg@example.com",
        password_hash=hash_password("AdminPw2026!"),
        role="admin",
    )
    db_session.add(admin)
    await db_session.commit()

    r = await client.post(
        "/auth/agent/register-with-credentials",
        json={
            "email": "admin-cred-reg@example.com",
            "password": "AdminPw2026!",
            "agent_name": "laptop-1",
            "client_version": "0.7.12",
        },
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "admin_cannot_register_agent"}}


@pytest.mark.asyncio
async def test_register_with_credentials_disabled_user(
    client: Any, db_session: AsyncSession
) -> None:
    user = User(
        email="disabled-cred-reg@example.com",
        password_hash=hash_password("DisabledPw2026!"),
        role="user",
        disabled=True,
    )
    db_session.add(user)
    await db_session.commit()

    r = await client.post(
        "/auth/agent/register-with-credentials",
        json={
            "email": "disabled-cred-reg@example.com",
            "password": "DisabledPw2026!",
            "agent_name": "laptop-1",
            "client_version": "0.7.12",
        },
    )
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "invalid_credentials"}}
