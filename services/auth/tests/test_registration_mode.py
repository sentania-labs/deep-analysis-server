"""Registration mode toggle tests (W3.6 sub-item 3).

Covers the GET + PUT endpoints under /admin/settings/registration-mode
and the UID=1-only ``require_root_admin`` gate. The auth-side default
is seeded by migration 003 — every test starts from
``invite_only`` (the conftest ``_truncate`` fixture resets the row).
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# GET /admin/settings/registration-mode — any admin may read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_returns_default_invite_only(client: Any, db_session: AsyncSession) -> None:
    # First user lands at id=1 thanks to RESTART IDENTITY in _truncate.
    uid = await _seed_user(db_session, email="root@example.com", role="admin")
    assert uid == 1
    token = await _login(client, "root@example.com", "pw")

    r = await client.get("/admin/settings/registration-mode", headers=_h(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "invite_only"
    assert "updated_at" in body
    # Migration's seeded default has no updated_by user yet.
    assert body["updated_by_user_id"] is None


@pytest.mark.asyncio
async def test_get_works_for_non_root_admin(client: Any, db_session: AsyncSession) -> None:
    # UID=1 is the root admin; UID=2 is a non-root admin and must
    # still be able to *read* the setting.
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.get("/admin/settings/registration-mode", headers=_h(token))
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "invite_only"


@pytest.mark.asyncio
async def test_get_rejects_non_admin(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.get("/admin/settings/registration-mode", headers=_h(token))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_rejects_unauthenticated(client: Any) -> None:
    r = await client.get("/admin/settings/registration-mode")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# PUT /admin/settings/registration-mode — UID=1 admin only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_root_admin_can_flip_to_open(client: Any, db_session: AsyncSession) -> None:
    uid = await _seed_user(db_session, email="root@example.com", role="admin")
    assert uid == 1
    token = await _login(client, "root@example.com", "pw")

    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "open"},
        headers=_h(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "open"
    assert body["updated_by_user_id"] == 1

    # Round-trip — GET reflects the flipped value.
    r2 = await client.get("/admin/settings/registration-mode", headers=_h(token))
    assert r2.status_code == 200
    assert r2.json()["mode"] == "open"


@pytest.mark.asyncio
async def test_put_root_admin_can_flip_back_to_invite_only(
    client: Any, db_session: AsyncSession
) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    # Flip → open then back → invite_only.
    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "open"},
        headers=_h(token),
    )
    assert r.status_code == 200
    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "invite_only"},
        headers=_h(token),
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "invite_only"


@pytest.mark.asyncio
async def test_put_non_root_admin_returns_403(client: Any, db_session: AsyncSession) -> None:
    # UID=1 is the root admin (untouched). UID=2 is also an admin but
    # not the root — must get 403 not_root_admin.
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="boss@example.com", role="admin")
    token = await _login(client, "boss@example.com", "pw")

    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "open"},
        headers=_h(token),
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "not_root_admin"}}

    # Confirm the value did not change — root admin reads back the
    # unchanged default.
    root_token = await _login(client, "root@example.com", "pw")
    r2 = await client.get("/admin/settings/registration-mode", headers=_h(root_token))
    assert r2.json()["mode"] == "invite_only"


@pytest.mark.asyncio
async def test_put_user_role_returns_403(client: Any, db_session: AsyncSession) -> None:
    # UID=1 admin; UID=2 plain user — must 403. require_root_admin is
    # the only gate on PUT so the error code is ``not_root_admin``
    # regardless of role. The role check inside the gate still matters
    # — see test_put_uid_one_user_role_still_blocked for the case
    # where UID=1 is not an admin.
    await _seed_user(db_session, email="root@example.com", role="admin")
    await _seed_user(db_session, email="member@example.com", role="user")
    token = await _login(client, "member@example.com", "pw")

    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "open"},
        headers=_h(token),
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "not_root_admin"}}


@pytest.mark.asyncio
async def test_put_uid_one_user_role_still_blocked(client: Any, db_session: AsyncSession) -> None:
    # Edge case: UID=1 happens to be a plain user (the bootstrap admin
    # was demoted, say). require_root_admin must reject because role
    # != admin, not just because user_id != 1 — defends against a
    # rogue demoted-but-still-UID-1 caller. The error code is
    # ``not_root_admin`` (the gate doesn't distinguish the two
    # failure modes — both mean "not the original installer admin").
    uid = await _seed_user(db_session, email="root@example.com", role="user")
    assert uid == 1
    token = await _login(client, "root@example.com", "pw")

    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "open"},
        headers=_h(token),
    )
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "not_root_admin"}}


@pytest.mark.asyncio
async def test_put_unauthenticated_returns_401(client: Any) -> None:
    r = await client.put("/admin/settings/registration-mode", json={"mode": "open"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_put_rejects_invalid_mode(client: Any, db_session: AsyncSession) -> None:
    await _seed_user(db_session, email="root@example.com", role="admin")
    token = await _login(client, "root@example.com", "pw")

    r = await client.put(
        "/admin/settings/registration-mode",
        json={"mode": "totally-not-a-mode"},
        headers=_h(token),
    )
    assert r.status_code == 422
