"""Admin tunables endpoint + DB-backed string-tunable plumbing.

Covers the version-constant tunables (parser_version, reparse_min_version,
min_agent_version) that landed when those fields moved from hardcoded
constants to server_settings rows admins can edit from the UI.
"""

from __future__ import annotations

from typing import Any

import pytest
from auth_service.admin import _read_string_tunable, read_min_agent_version
from auth_service.models import ServerSetting, User
from auth_service.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def _seed_admin(
    client: Any,
    db: AsyncSession,
    email: str = "admin@example.com",
    password: str = "pw",
) -> tuple[int, str]:
    u = User(email=email, password_hash=hash_password(password), role="admin")
    db.add(u)
    await db.commit()
    await db.refresh(u)
    token = await _login(client, email, password)
    return u.id, token


async def _seed_user(
    client: Any,
    db: AsyncSession,
    email: str = "regular@example.com",
    password: str = "pw",
) -> tuple[int, str]:
    u = User(email=email, password_hash=hash_password(password), role="user")
    db.add(u)
    await db.commit()
    await db.refresh(u)
    token = await _login(client, email, password)
    return u.id, token


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# String tunable read/fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_string_tunable_default_when_no_row(db_session: AsyncSession) -> None:
    # Fresh DB has no tunable:* rows. Compiled defaults apply.
    assert await _read_string_tunable(db_session, "min_agent_version") == "0.5.0"
    assert await _read_string_tunable(db_session, "parser_version") == "0.9.0"
    assert await _read_string_tunable(db_session, "reparse_min_version") == "0.9.0"


@pytest.mark.asyncio
async def test_read_min_agent_version_falls_back(db_session: AsyncSession) -> None:
    assert await read_min_agent_version(db_session) == "0.5.0"


# ---------------------------------------------------------------------------
# PATCH /admin/settings/tunables — string fields, round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_string_tunables_round_trip(
    client: Any, db_session: AsyncSession
) -> None:
    _admin_id, token = await _seed_admin(client, db_session)

    r = await client.patch(
        "/admin/settings/tunables",
        json={
            "parser_version": "0.10.1",
            "reparse_min_version": "0.10.0",
            "min_agent_version": "0.6.0",
        },
        headers=_h(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["parser_version"] == "0.10.1"
    assert body["reparse_min_version"] == "0.10.0"
    assert body["min_agent_version"] == "0.6.0"

    # DB rows landed
    db_session.expire_all()
    rows = {
        row.key: row.value
        for row in (
            (
                await db_session.execute(
                    select(ServerSetting).where(
                        ServerSetting.key.in_(
                            [
                                "tunable:parser_version",
                                "tunable:reparse_min_version",
                                "tunable:min_agent_version",
                            ]
                        )
                    )
                )
            )
            .scalars()
            .all()
        )
    }
    assert rows == {
        "tunable:parser_version": "0.10.1",
        "tunable:reparse_min_version": "0.10.0",
        "tunable:min_agent_version": "0.6.0",
    }

    # And read back through the helper
    assert await _read_string_tunable(db_session, "min_agent_version") == "0.6.0"


@pytest.mark.asyncio
async def test_patch_accepts_v_prefix_and_pre_release(
    client: Any, db_session: AsyncSession
) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.patch(
        "/admin/settings/tunables",
        json={"min_agent_version": "v0.6.0-rc1"},
        headers=_h(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["min_agent_version"] == "v0.6.0-rc1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    ["", "   ", "abc", "1.2", "1.2.x", "1.2.3.4", "not-a-version"],
)
async def test_patch_rejects_invalid_version_string(
    client: Any, db_session: AsyncSession, value: str
) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.patch(
        "/admin/settings/tunables",
        json={"min_agent_version": value},
        headers=_h(token),
    )
    # Pydantic-level reject (422) or our explicit field-level 400.
    assert r.status_code in (400, 422), r.text
    if r.status_code == 400:
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_version"
        assert detail["field"] == "min_agent_version"


@pytest.mark.asyncio
async def test_patch_string_tunable_requires_admin(
    client: Any, db_session: AsyncSession
) -> None:
    _user_id, token = await _seed_user(client, db_session)
    r = await client.patch(
        "/admin/settings/tunables",
        json={"min_agent_version": "0.6.0"},
        headers=_h(token),
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /admin/settings/tunables — surfaces DB value or compiled default
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_tunables_surfaces_defaults(
    client: Any, db_session: AsyncSession
) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.get("/admin/settings/tunables", headers=_h(token))
    assert r.status_code == 200
    body = r.json()
    assert body["parser_version"] == "0.9.0"
    assert body["reparse_min_version"] == "0.9.0"
    assert body["min_agent_version"] == "0.5.0"


# ---------------------------------------------------------------------------
# Heartbeat gate — reads from DB, falls back to compiled default
# ---------------------------------------------------------------------------


async def _register_agent(
    client: Any, email: str, password: str
) -> dict[str, Any]:
    access = await _login(client, email, password)
    r = await client.post(
        "/auth/agent/registration-code",
        headers=_h(access),
    )
    assert r.status_code == 201, r.text
    code = r.json()["code"]
    r = await client.post(
        "/auth/agent/register",
        json={"code": code, "machine_name": "lab-1", "client_version": "0.5.0"},
    )
    assert r.status_code == 201, r.text
    return dict(r.json())


@pytest.mark.asyncio
async def test_heartbeat_min_agent_version_falls_back_to_default(
    client: Any, db_session: AsyncSession, seed_user: dict[str, Any]
) -> None:
    agent = await _register_agent(client, seed_user["email"], seed_user["password"])
    r = await client.post(
        "/auth/agent/heartbeat",
        headers=_h(agent["api_token"]),
        json={},
    )
    assert r.status_code == 200, r.text
    assert r.json()["min_agent_version"] == "0.5.0"


@pytest.mark.asyncio
async def test_heartbeat_min_agent_version_reads_db_override(
    client: Any, db_session: AsyncSession, seed_user: dict[str, Any]
) -> None:
    # Save through the admin endpoint so the DB row is written by the
    # same path production uses.
    _admin_id, admin_token = await _seed_admin(client, db_session)
    r = await client.patch(
        "/admin/settings/tunables",
        json={"min_agent_version": "0.6.0"},
        headers=_h(admin_token),
    )
    assert r.status_code == 200, r.text

    agent = await _register_agent(client, seed_user["email"], seed_user["password"])
    r = await client.post(
        "/auth/agent/heartbeat",
        headers=_h(agent["api_token"]),
        json={},
    )
    assert r.status_code == 200, r.text
    assert r.json()["min_agent_version"] == "0.6.0"


@pytest.mark.asyncio
async def test_patch_no_op_payload_rejected(
    client: Any, db_session: AsyncSession
) -> None:
    _admin_id, token = await _seed_admin(client, db_session)
    r = await client.patch("/admin/settings/tunables", json={}, headers=_h(token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_unauthenticated(client: Any) -> None:
    r = await client.patch(
        "/admin/settings/tunables",
        json={"min_agent_version": "0.6.0"},
    )
    assert r.status_code == 401
