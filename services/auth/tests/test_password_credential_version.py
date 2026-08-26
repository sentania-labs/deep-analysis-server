"""Credential-version (password_changed_at / password_epoch) behaviour.

Covers the Codex review findings on PR #143 that the plain
"revoke the rows we can see" approach could not cover:

- a session issued against the pre-reset user row is rejected even when
  its row only becomes visible after the reset committed (the race);
- ``/auth/refresh`` cannot mint a fresh access token from such a
  session;
- already-expired sessions are not counted as revoked;
- the migration alone does not sign anybody out.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auth_service.jwt_issue import hash_refresh_token, issue_access_token
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _seed_admin(client: Any, db: AsyncSession) -> str:
    u = User(email="cvadmin@example.com", password_hash=hash_password("pw"), role="admin")
    db.add(u)
    await db.commit()
    r = await client.post("/auth/login", json={"email": "cvadmin@example.com", "password": "pw"})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def _seed_user(db: AsyncSession, email: str, *, password_changed_at: Any = None) -> User:
    u = User(
        email=email,
        password_hash=hash_password("originalpw"),
        role="user",
        password_changed_at=password_changed_at,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


async def _insert_session(
    db: AsyncSession,
    user: User,
    *,
    password_epoch: Any,
    issued_at: datetime,
    expires_at: datetime,
    refresh_token: str | None = None,
) -> SessionRow:
    row = SessionRow(
        user_id=user.id,
        refresh_token_hash=(
            hash_refresh_token(refresh_token) if refresh_token else uuid.uuid4().hex
        ),
        issued_at=issued_at,
        expires_at=expires_at,
        password_epoch=password_epoch,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


@pytest.mark.asyncio
async def test_session_racing_the_reset_is_rejected(client: Any, db_session: AsyncSession) -> None:
    """The race Codex called out (finding 2), constructed deliberately.

    A login authenticates against the pre-reset user row, so it stamps
    the pre-reset credential version onto its session. Its INSERT lands
    only after the reset's transaction has already taken its snapshot,
    so the reset's revocation query never sees it. We reproduce that by
    inserting the row after the reset returns.

    ``issued_at`` is deliberately set *later* than the reset. A check
    that merely compared issued_at against password_changed_at would
    wave this session through; the credential-version equality check
    does not, because the session carries the epoch its login read.
    """
    admin_token = await _seed_admin(client, db_session)
    target = await _seed_user(db_session, "racer@example.com")

    # What a login reads off the user row before the reset commits.
    epoch_seen_by_racing_login = target.password_changed_at
    assert epoch_seen_by_racing_login is None

    r = await client.post(f"/admin/users/{target.id}/reset-password", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    # Nothing to revoke: the racing session's row does not exist yet.
    assert r.json()["revoked_sessions"] == 0

    await db_session.refresh(target)
    assert target.password_changed_at is not None

    # The racing login's INSERT finally lands, stamped with the stale
    # epoch and a timestamp later than the reset.
    later = datetime.now(UTC) + timedelta(seconds=30)
    row = await _insert_session(
        db_session,
        target,
        password_epoch=epoch_seen_by_racing_login,
        issued_at=later,
        expires_at=later + timedelta(days=1),
    )
    assert row.revoked_at is None
    assert row.issued_at > target.password_changed_at

    token = issue_access_token(target.id, target.role, row.id, email=target.email)
    assert (await client.get("/auth/me", headers=_h(token))).status_code == 401


@pytest.mark.asyncio
async def test_refresh_cannot_mint_from_pre_reset_session(
    client: Any, db_session: AsyncSession
) -> None:
    """/auth/refresh honours the credential version (finding 2, refresh path)."""
    admin_token = await _seed_admin(client, db_session)
    target = await _seed_user(db_session, "refresher@example.com")

    # Ordinary case: log in, then get reset. The session is revoked
    # outright, and refresh must not resurrect it.
    r = await client.post(
        "/auth/login", json={"email": "refresher@example.com", "password": "originalpw"}
    )
    assert r.status_code == 200, r.text
    live_refresh = r.json()["refresh_token"]

    r = await client.post(f"/admin/users/{target.id}/reset-password", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["revoked_sessions"] == 1

    r = await client.post("/auth/refresh", json={"refresh_token": live_refresh})
    assert r.status_code == 401

    # Race case: an unrevoked session row carrying the stale epoch. Only
    # the credential-version check can reject this one.
    await db_session.refresh(target)
    racing_refresh = uuid.uuid4().hex
    now = datetime.now(UTC)
    await _insert_session(
        db_session,
        target,
        password_epoch=None,
        issued_at=now + timedelta(seconds=30),
        expires_at=now + timedelta(days=1),
        refresh_token=racing_refresh,
    )
    r = await client.post("/auth/refresh", json={"refresh_token": racing_refresh})
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_expired_sessions_are_not_counted_as_revoked(
    client: Any, db_session: AsyncSession
) -> None:
    """Finding 3: expired-but-unrevoked rows must not inflate the count.

    Authentication already rejects them, so counting them would tell the
    admin that browsers were signed out when nothing live existed.
    """
    admin_token = await _seed_admin(client, db_session)
    target = await _seed_user(db_session, "expired@example.com")

    now = datetime.now(UTC)
    for _ in range(3):
        await _insert_session(
            db_session,
            target,
            password_epoch=target.password_changed_at,
            issued_at=now - timedelta(days=40),
            expires_at=now - timedelta(days=10),
        )
    live = await _insert_session(
        db_session,
        target,
        password_epoch=target.password_changed_at,
        issued_at=now,
        expires_at=now + timedelta(days=1),
    )

    r = await client.post(f"/admin/users/{target.id}/reset-password", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["revoked_sessions"] == 1

    await db_session.refresh(live)
    assert live.revoked_at is not None


@pytest.mark.asyncio
async def test_expired_sessions_are_not_counted_by_revoke_sessions_endpoint(
    client: Any, db_session: AsyncSession
) -> None:
    """The standalone revoke-sessions count means the same thing."""
    admin_token = await _seed_admin(client, db_session)
    target = await _seed_user(db_session, "expired2@example.com")

    now = datetime.now(UTC)
    await _insert_session(
        db_session,
        target,
        password_epoch=None,
        issued_at=now - timedelta(days=40),
        expires_at=now - timedelta(days=10),
    )
    await _insert_session(
        db_session,
        target,
        password_epoch=None,
        issued_at=now,
        expires_at=now + timedelta(days=1),
    )

    r = await client.post(f"/admin/users/{target.id}/revoke-sessions", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["revoked_count"] == 1


@pytest.mark.asyncio
async def test_migration_alone_does_not_sign_existing_users_out(
    client: Any, db_session: AsyncSession
) -> None:
    """Deploy safety: NULL on both sides is a match, not a mismatch.

    This is the exact post-migration state: existing users have
    ``password_changed_at IS NULL`` and their existing session rows have
    ``password_epoch IS NULL`` because both columns were backfilled
    NULL. Those sessions must keep working.
    """
    target = await _seed_user(db_session, "predeploy@example.com", password_changed_at=None)
    now = datetime.now(UTC)
    row = await _insert_session(
        db_session,
        target,
        password_epoch=None,
        issued_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=29),
        refresh_token="pre-deploy-refresh-token",
    )

    stored = (await db_session.execute(select(User).where(User.id == target.id))).scalar_one()
    assert stored.password_changed_at is None

    token = issue_access_token(target.id, target.role, row.id, email=target.email)
    r = await client.get("/auth/me", headers=_h(token))
    assert r.status_code == 200, r.text

    # And the refresh path still rotates it.
    r = await client.post("/auth/refresh", json={"refresh_token": "pre-deploy-refresh-token"})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_self_service_change_moves_the_credential_version(
    client: Any, db_session: AsyncSession
) -> None:
    """POST /auth/password/change stamps password_changed_at too."""
    target = await _seed_user(db_session, "selfchange@example.com")
    r = await client.post(
        "/auth/login", json={"email": "selfchange@example.com", "password": "originalpw"}
    )
    assert r.status_code == 200, r.text
    access = r.json()["access_token"]

    r = await client.post(
        "/auth/password/change",
        json={"current_password": "originalpw", "new_password": "a-much-longer-password"},
        headers=_h(access),
    )
    assert r.status_code == 204, r.text

    await db_session.refresh(target)
    assert target.password_changed_at is not None

    # A session racing that change carries the pre-change epoch.
    now = datetime.now(UTC)
    row = await _insert_session(
        db_session,
        target,
        password_epoch=None,
        issued_at=now + timedelta(seconds=30),
        expires_at=now + timedelta(days=1),
    )
    stale = issue_access_token(target.id, target.role, row.id, email=target.email)
    assert (await client.get("/auth/me", headers=_h(stale))).status_code == 401
