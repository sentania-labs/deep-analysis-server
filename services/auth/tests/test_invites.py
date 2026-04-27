"""Invite token tests (W3.6 sub-item 4).

Covers:
- POST /admin/invites: admin-only, returns plaintext once, hashes at rest.
- GET /admin/invites: lists pending only, paginated.
- DELETE /admin/invites/{id}: revoke marks expires_at = now().
- POST /auth/register: invite_only mode requires + consumes token,
  open mode optional-but-consumed-if-present, single-use enforced,
  expired tokens rejected, email uniqueness + password complexity.
- GET /auth/registration-mode: public read.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auth_service.models import InviteToken, User
from auth_service.passwords import hash_password
from auth_service.registration import hash_invite_token
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def _seed_user(
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


async def _set_mode(db: AsyncSession, mode: str) -> None:
    await db.execute(
        text(
            "UPDATE auth.server_settings "
            "SET value = (:mode)::jsonb, updated_at = now() "
            "WHERE key = 'registration_mode'"
        ),
        {"mode": f'"{mode}"'},
    )
    await db.commit()


# ---------------------------------------------------------------------------
# POST /admin/invites — create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_invite_returns_plaintext_and_hashes_at_rest(
    client: Any, db_session: AsyncSession
) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.post("/admin/invites", json={}, headers=_h(token))
    assert r.status_code == 201, r.text
    body = r.json()
    assert "token" in body
    assert "id" in body
    plaintext = body["token"]
    assert len(plaintext) >= 20  # opaque, URL-safe, 32 bytes of entropy

    # Persisted row must hold the hash, never the plaintext.
    row = (
        await db_session.execute(select(InviteToken).where(InviteToken.id == uuid.UUID(body["id"])))
    ).scalar_one()
    assert row.token_hash == hash_invite_token(plaintext)
    assert row.token_hash != plaintext
    assert row.created_by_user_id == 1
    assert row.used_at is None
    # Default 168h ≈ 7 days from now (allow 5 min slack for test runtime).
    delta = row.expires_at - datetime.now(UTC)
    assert timedelta(hours=167, minutes=55) < delta < timedelta(hours=168, minutes=5)


@pytest.mark.asyncio
async def test_create_invite_honors_expires_in_hours(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.post("/admin/invites", json={"expires_in_hours": 24}, headers=_h(token))
    assert r.status_code == 201
    expires_at = datetime.fromisoformat(r.json()["expires_at"].replace("Z", "+00:00"))
    delta = expires_at - datetime.now(UTC)
    assert timedelta(hours=23, minutes=55) < delta < timedelta(hours=24, minutes=5)


@pytest.mark.asyncio
async def test_create_invite_rejects_above_max_hours(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.post("/admin/invites", json={"expires_in_hours": 1000}, headers=_h(token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_invite_rejects_zero_or_negative_hours(
    client: Any, db_session: AsyncSession
) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.post("/admin/invites", json={"expires_in_hours": 0}, headers=_h(token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_invite_rejects_non_admin(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.post("/admin/invites", json={}, headers=_h(token))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_create_invite_rejects_unauthenticated(client: Any) -> None:
    r = await client.post("/admin/invites", json={})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_invite_any_admin_can_mint(client: Any, db_session: AsyncSession) -> None:
    """Spec: any admin can mint, not just UID=1."""
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.post("/admin/invites", json={}, headers=_h(token))
    assert r.status_code == 201, r.text
    assert r.json()["token"]


# ---------------------------------------------------------------------------
# GET /admin/invites — list pending
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_invites_returns_pending_only(client: Any, db_session: AsyncSession) -> None:
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    now = datetime.now(UTC)
    pending = InviteToken(
        token_hash=hash_invite_token("pending-tok"),
        created_by_user_id=admin_id,
        created_at=now,
        expires_at=now + timedelta(hours=168),
    )
    expired = InviteToken(
        token_hash=hash_invite_token("expired-tok"),
        created_by_user_id=admin_id,
        created_at=now - timedelta(hours=200),
        expires_at=now - timedelta(hours=1),
    )
    used = InviteToken(
        token_hash=hash_invite_token("used-tok"),
        created_by_user_id=admin_id,
        created_at=now,
        expires_at=now + timedelta(hours=168),
        used_at=now,
        used_by_user_id=admin_id,
    )
    db_session.add_all([pending, expired, used])
    await db_session.commit()

    r = await client.get("/admin/invites", headers=_h(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 1
    assert len(body["invites"]) == 1
    assert body["invites"][0]["created_by_email"] == "root@example.com"


@pytest.mark.asyncio
async def test_list_invites_pagination(client: Any, db_session: AsyncSession) -> None:
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    now = datetime.now(UTC)
    for i in range(5):
        db_session.add(
            InviteToken(
                token_hash=hash_invite_token(f"tok-{i}"),
                created_by_user_id=admin_id,
                created_at=now + timedelta(seconds=i),
                expires_at=now + timedelta(hours=168),
            )
        )
    await db_session.commit()

    r = await client.get("/admin/invites?page=1&per_page=2", headers=_h(token))
    assert r.status_code == 200
    assert r.json()["total"] == 5
    assert len(r.json()["invites"]) == 2

    r = await client.get("/admin/invites?page=3&per_page=2", headers=_h(token))
    assert r.status_code == 200
    assert len(r.json()["invites"]) == 1


@pytest.mark.asyncio
async def test_list_invites_per_page_capped_at_200(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.get("/admin/invites?per_page=999", headers=_h(token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_list_invites_rejects_non_admin(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.get("/admin/invites", headers=_h(token))
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /admin/invites/{id} — revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_invite_marks_expired(client: Any, db_session: AsyncSession) -> None:
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    now = datetime.now(UTC)
    invite = InviteToken(
        token_hash=hash_invite_token("victim"),
        created_by_user_id=admin_id,
        created_at=now,
        expires_at=now + timedelta(hours=168),
    )
    db_session.add(invite)
    await db_session.commit()
    await db_session.refresh(invite)

    invite_id = invite.id
    r = await client.delete(f"/admin/invites/{invite_id}", headers=_h(token))
    assert r.status_code == 204

    # Row still present (audit trail), but expires_at is now in the past.
    # Drop identity-map cached values so we re-read from the DB and pick
    # up the auth-service handler's UPDATE.
    db_session.expunge_all()
    refreshed = (
        await db_session.execute(select(InviteToken).where(InviteToken.id == invite_id))
    ).scalar_one()
    assert refreshed.expires_at <= datetime.now(UTC) + timedelta(seconds=1)
    assert refreshed.used_at is None

    # And it no longer appears in the pending list.
    r = await client.get("/admin/invites", headers=_h(token))
    assert r.status_code == 200
    assert r.json()["total"] == 0


@pytest.mark.asyncio
async def test_revoke_invite_404_when_missing(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.delete(f"/admin/invites/{uuid.uuid4()}", headers=_h(token))
    assert r.status_code == 404
    assert r.json() == {"detail": {"error": "invite_not_found"}}


@pytest.mark.asyncio
async def test_revoke_invite_rejects_non_admin(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.delete(f"/admin/invites/{uuid.uuid4()}", headers=_h(token))
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /auth/registration-mode — public
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_public_registration_mode_returns_default(client: Any) -> None:
    r = await client.get("/auth/registration-mode")
    assert r.status_code == 200
    assert r.json() == {"mode": "invite_only"}


@pytest.mark.asyncio
async def test_public_registration_mode_reflects_change(
    client: Any, db_session: AsyncSession
) -> None:
    await _set_mode(db_session, "open")
    r = await client.get("/auth/registration-mode")
    assert r.status_code == 200
    assert r.json() == {"mode": "open"}


# ---------------------------------------------------------------------------
# POST /auth/register — invite_only mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_invite_only_requires_token(client: Any, db_session: AsyncSession) -> None:
    # Mode default is invite_only after _truncate.
    r = await client.post(
        "/auth/register",
        json={"email": "new@example.com", "password": "longenoughpw!!"},
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "invite_required"}}

    # User row was NOT created.
    row = (
        await db_session.execute(select(User).where(User.email == "new@example.com"))
    ).scalar_one_or_none()
    assert row is None


@pytest.mark.asyncio
async def test_register_invite_only_invalid_token_returns_403(
    client: Any, db_session: AsyncSession
) -> None:
    r = await client.post(
        "/auth/register",
        json={
            "email": "new@example.com",
            "password": "longenoughpw!!",
            "token": "not-a-real-token",
        },
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "invalid_invite_token"}}


@pytest.mark.asyncio
async def test_register_invite_only_happy_path_consumes_token(
    client: Any, db_session: AsyncSession
) -> None:
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    plaintext = "test-invite-token-abc123"
    invite = InviteToken(
        token_hash=hash_invite_token(plaintext),
        created_by_user_id=admin_id,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=168),
    )
    db_session.add(invite)
    await db_session.commit()
    await db_session.refresh(invite)
    invite_id = invite.id

    r = await client.post(
        "/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "longenoughpw!!",
            "token": plaintext,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "newuser@example.com"
    new_user_id = int(body["user_id"])

    # User created with role=user, not admin, and not forced to change pw.
    user = (await db_session.execute(select(User).where(User.id == new_user_id))).scalar_one()
    assert user.role == "user"
    assert user.must_change_password is False
    assert user.disabled is False

    # Invite is now used.
    db_session.expunge_all()
    refreshed = (
        await db_session.execute(select(InviteToken).where(InviteToken.id == invite_id))
    ).scalar_one()
    assert refreshed.used_at is not None
    assert refreshed.used_by_user_id == new_user_id


@pytest.mark.asyncio
async def test_register_token_single_use_enforcement(client: Any, db_session: AsyncSession) -> None:
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    plaintext = "single-use-tok-xyz"
    invite = InviteToken(
        token_hash=hash_invite_token(plaintext),
        created_by_user_id=admin_id,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=168),
    )
    db_session.add(invite)
    await db_session.commit()

    # First use succeeds.
    r1 = await client.post(
        "/auth/register",
        json={
            "email": "first@example.com",
            "password": "longenoughpw!!",
            "token": plaintext,
        },
    )
    assert r1.status_code == 201

    # Second use fails — token already consumed.
    r2 = await client.post(
        "/auth/register",
        json={
            "email": "second@example.com",
            "password": "longenoughpw!!",
            "token": plaintext,
        },
    )
    assert r2.status_code == 403
    assert r2.json() == {"detail": {"error": "invalid_invite_token"}}


@pytest.mark.asyncio
async def test_register_concurrent_consumption_only_one_wins(
    client: Any, db_session: AsyncSession
) -> None:
    """Two parallel POST /auth/register calls racing the same token: one
    wins (201), one loses (403 invalid_invite_token). Guards against the
    SELECT-then-UPDATE race that lets both observe the row as unused.
    """
    import asyncio

    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    plaintext = "race-token-xyz"
    invite = InviteToken(
        token_hash=hash_invite_token(plaintext),
        created_by_user_id=admin_id,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=168),
    )
    db_session.add(invite)
    await db_session.commit()

    async def attempt(email: str) -> Any:
        return await client.post(
            "/auth/register",
            json={
                "email": email,
                "password": "longenoughpw!!",
                "token": plaintext,
            },
        )

    r1, r2 = await asyncio.gather(
        attempt("racer-a@example.com"),
        attempt("racer-b@example.com"),
    )
    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [201, 403], (r1.status_code, r1.text, r2.status_code, r2.text)

    loser = r1 if r1.status_code == 403 else r2
    assert loser.json() == {"detail": {"error": "invalid_invite_token"}}

    # Exactly one user was created.
    users = (
        (
            await db_session.execute(
                select(User).where(User.email.in_(["racer-a@example.com", "racer-b@example.com"]))
            )
        )
        .scalars()
        .all()
    )
    assert len(users) == 1


@pytest.mark.asyncio
async def test_register_expired_token_rejected(client: Any, db_session: AsyncSession) -> None:
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    plaintext = "expired-tok"
    invite = InviteToken(
        token_hash=hash_invite_token(plaintext),
        created_by_user_id=admin_id,
        created_at=datetime.now(UTC) - timedelta(hours=200),
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    db_session.add(invite)
    await db_session.commit()

    r = await client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "longenoughpw!!",
            "token": plaintext,
        },
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "invalid_invite_token"}}


# ---------------------------------------------------------------------------
# POST /auth/register — open mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_open_mode_no_token_succeeds(client: Any, db_session: AsyncSession) -> None:
    await _set_mode(db_session, "open")

    r = await client.post(
        "/auth/register",
        json={"email": "open@example.com", "password": "longenoughpw!!"},
    )
    assert r.status_code == 201, r.text
    user = (
        await db_session.execute(select(User).where(User.email == "open@example.com"))
    ).scalar_one()
    assert user.role == "user"


@pytest.mark.asyncio
async def test_register_open_mode_consumes_token_if_provided(
    client: Any, db_session: AsyncSession
) -> None:
    """Open mode: token optional but consumed if provided."""
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    await _set_mode(db_session, "open")

    plaintext = "audit-tok"
    invite = InviteToken(
        token_hash=hash_invite_token(plaintext),
        created_by_user_id=admin_id,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=168),
    )
    db_session.add(invite)
    await db_session.commit()
    await db_session.refresh(invite)
    invite_id = invite.id

    r = await client.post(
        "/auth/register",
        json={
            "email": "u@example.com",
            "password": "longenoughpw!!",
            "token": plaintext,
        },
    )
    assert r.status_code == 201

    db_session.expunge_all()
    refreshed = (
        await db_session.execute(select(InviteToken).where(InviteToken.id == invite_id))
    ).scalar_one()
    assert refreshed.used_at is not None


@pytest.mark.asyncio
async def test_register_open_mode_invalid_token_still_rejected(
    client: Any, db_session: AsyncSession
) -> None:
    """Open mode + bad token = 403, not silent fall-through."""
    await _set_mode(db_session, "open")
    r = await client.post(
        "/auth/register",
        json={
            "email": "u@example.com",
            "password": "longenoughpw!!",
            "token": "definitely-not-real",
        },
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "invalid_invite_token"}}


# ---------------------------------------------------------------------------
# POST /auth/register — common validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_email_uniqueness(client: Any, db_session: AsyncSession) -> None:
    await _set_mode(db_session, "open")
    await _seed_user(db_session, email="taken@example.com", role="user")

    r = await client.post(
        "/auth/register",
        json={"email": "taken@example.com", "password": "longenoughpw!!"},
    )
    assert r.status_code == 409
    assert r.json() == {"detail": {"error": "email_already_exists"}}

    # Case-insensitive collision.
    r = await client.post(
        "/auth/register",
        json={"email": "TAKEN@example.com", "password": "longenoughpw!!"},
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_register_password_complexity(client: Any, db_session: AsyncSession) -> None:
    await _set_mode(db_session, "open")
    r = await client.post(
        "/auth/register",
        json={"email": "u@example.com", "password": "short"},
    )
    assert r.status_code == 400
    assert r.json() == {"detail": {"error": "weak_password"}}


@pytest.mark.asyncio
async def test_register_invite_only_password_complexity_still_enforced(
    client: Any, db_session: AsyncSession
) -> None:
    """Token presence does NOT short-circuit password policy."""
    admin_id = await _seed_user(db_session, email="root@example.com", role="admin")
    plaintext = "valid-tok"
    invite = InviteToken(
        token_hash=hash_invite_token(plaintext),
        created_by_user_id=admin_id,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=168),
    )
    db_session.add(invite)
    await db_session.commit()

    r = await client.post(
        "/auth/register",
        json={
            "email": "u@example.com",
            "password": "tiny",
            "token": plaintext,
        },
    )
    assert r.status_code == 400
    assert r.json() == {"detail": {"error": "weak_password"}}


# ---------------------------------------------------------------------------
# Full flow integration — admin mints, user registers, user logs in
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_invite_flow(client: Any, db_session: AsyncSession) -> None:
    # Admin mints an invite.
    await _seed_user(db_session, email="root@example.com", role="admin")
    admin_token = await _login(client, "root@example.com", "pw")

    r = await client.post("/admin/invites", json={}, headers=_h(admin_token))
    assert r.status_code == 201
    invite_token = r.json()["token"]

    # User registers with the invite.
    r = await client.post(
        "/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "longenoughpw!!",
            "token": invite_token,
        },
    )
    assert r.status_code == 201

    # New user can log in with their chosen password.
    user_token = await _login(client, "newuser@example.com", "longenoughpw!!")
    r = await client.get("/auth/me", headers=_h(user_token))
    assert r.status_code == 200
    me = r.json()
    assert me["email"] == "newuser@example.com"
    assert me["role"] == "user"
    assert me["must_change_password"] is False


@pytest.mark.asyncio
async def test_full_invite_flow_token_appears_only_once(
    client: Any, db_session: AsyncSession
) -> None:
    """Plaintext token is in POST /admin/invites response but not GET list."""
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.post("/admin/invites", json={}, headers=_h(token))
    assert r.status_code == 201
    plaintext = r.json()["token"]

    r = await client.get("/admin/invites", headers=_h(token))
    body = r.json()
    serialized = str(body)
    assert plaintext not in serialized
