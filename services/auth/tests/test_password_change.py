"""Must-change-password login + POST /auth/password/change tests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import jwt
import pytest
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import hash_password, verify_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _decode(token: str) -> dict[str, Any]:
    pub = Path(os.environ["DA_JWT_PUBLIC_KEY_PATH"]).read_text()
    return jwt.decode(token, pub, algorithms=["RS256"], audience="deep-analysis")


async def _make_user(
    db: AsyncSession,
    email: str,
    password: str = "old-password",
    must_change: bool = True,
    role: str = "user",
) -> User:
    u = User(
        email=email,
        password_hash=hash_password(password),
        role=role,
        must_change_password=must_change,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


@pytest.mark.asyncio
async def test_mcp_login_returns_scoped_short_lived_token(
    client: Any, db_session: AsyncSession
) -> None:
    await _make_user(db_session, "a@example.com", must_change=True)
    r = await client.post(
        "/auth/login", json={"email": "a@example.com", "password": "old-password"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["must_change_password"] is True
    assert body["expires_in"] == 300
    claims = _decode(body["access_token"])
    assert claims["scope"] == "password-change-only"
    # ~5 minutes between iat and exp
    assert 200 < claims["exp"] - claims["iat"] <= 300


@pytest.mark.asyncio
async def test_scoped_token_rejected_on_me(client: Any, db_session: AsyncSession) -> None:
    await _make_user(db_session, "b@example.com", must_change=True)
    r = await client.post(
        "/auth/login", json={"email": "b@example.com", "password": "old-password"}
    )
    token = r.json()["access_token"]
    r2 = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 403
    assert r2.json() == {"detail": {"error": "password_change_required"}}


@pytest.mark.asyncio
async def test_scoped_token_rejected_on_admin_endpoint(
    client: Any, db_session: AsyncSession
) -> None:
    await _make_user(db_session, "admin1@example.com", must_change=True, role="admin")
    r = await client.post(
        "/auth/login", json={"email": "admin1@example.com", "password": "old-password"}
    )
    token = r.json()["access_token"]
    r2 = await client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 403
    assert r2.json() == {"detail": {"error": "password_change_required"}}


@pytest.mark.asyncio
async def test_password_change_success(client: Any, db_session: AsyncSession) -> None:
    u = await _make_user(db_session, "c@example.com", must_change=True)
    r = await client.post(
        "/auth/login", json={"email": "c@example.com", "password": "old-password"}
    )
    token = r.json()["access_token"]

    r2 = await client.post(
        "/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "old-password", "new_password": "new-super-long-password"},
    )
    assert r2.status_code == 204, r2.text

    await db_session.refresh(u)
    assert u.must_change_password is False
    assert verify_password("new-super-long-password", u.password_hash)

    sessions = (
        (await db_session.execute(select(SessionRow).where(SessionRow.user_id == u.id)))
        .scalars()
        .all()
    )
    assert all(s.revoked_at is not None for s in sessions)


@pytest.mark.asyncio
async def test_subsequent_login_full_scope(client: Any, db_session: AsyncSession) -> None:
    u = await _make_user(db_session, "d@example.com", must_change=True)
    r = await client.post(
        "/auth/login", json={"email": "d@example.com", "password": "old-password"}
    )
    token = r.json()["access_token"]
    r2 = await client.post(
        "/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "old-password", "new_password": "another-long-password"},
    )
    assert r2.status_code == 204

    r3 = await client.post(
        "/auth/login", json={"email": "d@example.com", "password": "another-long-password"}
    )
    assert r3.status_code == 200
    body = r3.json()
    assert body["must_change_password"] is False
    assert body["expires_in"] == 900
    claims = _decode(body["access_token"])
    assert "scope" not in claims

    # /auth/me now works with the new token
    r4 = await client.get("/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r4.status_code == 200
    assert r4.json()["user_id"] == u.id


@pytest.mark.asyncio
async def test_weak_password_rejected(client: Any, db_session: AsyncSession) -> None:
    await _make_user(db_session, "e@example.com", must_change=True)
    r = await client.post(
        "/auth/login", json={"email": "e@example.com", "password": "old-password"}
    )
    token = r.json()["access_token"]
    r2 = await client.post(
        "/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "old-password", "new_password": "short"},
    )
    assert r2.status_code == 400
    assert r2.json() == {"detail": {"error": "weak_password"}}


@pytest.mark.asyncio
async def test_wrong_current_password(client: Any, db_session: AsyncSession) -> None:
    await _make_user(db_session, "f@example.com", must_change=True)
    r = await client.post(
        "/auth/login", json={"email": "f@example.com", "password": "old-password"}
    )
    token = r.json()["access_token"]
    r2 = await client.post(
        "/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "WRONG", "new_password": "a-strong-new-password"},
    )
    assert r2.status_code == 401
    assert r2.json() == {"detail": {"error": "invalid_credentials"}}


@pytest.mark.asyncio
async def test_password_change_deletes_initial_admin_file(
    client: Any, db_session: AsyncSession, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from auth_service import settings as _settings

    secret = tmp_path / "initial_admin.txt"
    secret.write_text("fake-password\n")

    # Patch the cached settings to redirect the secret path.
    current = _settings.get_settings()
    monkeypatch.setattr(current, "initial_admin_secret_path", secret)

    await _make_user(db_session, "admin@local", must_change=True, role="admin")
    r = await client.post("/auth/login", json={"email": "admin@local", "password": "old-password"})
    token = r.json()["access_token"]
    r2 = await client.post(
        "/auth/password/change",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "old-password", "new_password": "a-fine-long-password"},
    )
    assert r2.status_code == 204
    assert not secret.exists()
