"""Upload endpoint — agent version gate (HTTP 426 Upgrade Required).

Covers: version below minimum, at minimum, above minimum, missing
client_version, missing tunable (uses compiled default), and
unparseable agent version.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.token_utils import hash_api_token


def _auth_header(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


async def _seed_agent_with_version(
    db: AsyncSession,
    client_version: str | None,
) -> dict[str, Any]:
    """Create a user + agent registration with an explicit client_version."""
    user_email = f"u-{uuid.uuid4().hex[:8]}@example.com"
    user_row = (
        await db.execute(
            text(
                "INSERT INTO auth.users (email, password_hash, role) "
                "VALUES (:e, :h, 'user') RETURNING id"
            ),
            {"e": user_email, "h": "x" * 64},
        )
    ).scalar_one()

    api_token = secrets.token_urlsafe(32)
    agent_row = (
        await db.execute(
            text(
                "INSERT INTO auth.agent_registrations "
                "(user_id, machine_name, api_token_hash, client_version) "
                "VALUES (:u, :m, :h, :v) RETURNING id"
            ),
            {
                "u": user_row,
                "m": "test-machine",
                "h": hash_api_token(api_token),
                "v": client_version,
            },
        )
    ).scalar_one()
    await db.commit()
    return {"user_id": int(user_row), "agent_id": agent_row, "api_token": api_token}


async def _set_min_agent_version(db: AsyncSession, version: str) -> None:
    """Insert or update the min_agent_version tunable in server_settings."""
    await db.execute(
        text(
            "INSERT INTO auth.server_settings (key, value) "
            "VALUES ('tunable:min_agent_version', :v) "
            "ON CONFLICT (key) DO UPDATE SET value = :v"
        ),
        {"v": version},
    )
    await db.commit()
    # Bust the in-process cache so the test picks up the new value.
    from ingest_service.main import reset_min_version_cache

    reset_min_version_cache()


async def _upload(client: AsyncClient, api_token: str) -> Any:
    """Fire a minimal upload request; return the httpx Response."""
    return await client.post(
        "/ingest/upload",
        files={"file": ("x.dat", b"version-gate-test")},
        data={"content_type": "match-log"},
        headers=_auth_header(api_token),
    )


# -- Tests -----------------------------------------------------------------


async def test_upload_rejected_when_below_min_version(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Agent at 0.4.0, minimum at 0.5.0 -> 426."""
    agent = await _seed_agent_with_version(db_session, "0.4.0")
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 426
    body = r.json()
    assert body["detail"] == "Agent upgrade required"
    assert body["min_version"] == "0.5.0"


async def test_upload_allowed_when_at_min_version(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Agent at 0.5.0, minimum at 0.5.0 -> allowed (201)."""
    agent = await _seed_agent_with_version(db_session, "0.5.0")
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 201


async def test_upload_allowed_when_above_min_version(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Agent at 0.6.0, minimum at 0.5.0 -> allowed (201)."""
    agent = await _seed_agent_with_version(db_session, "0.6.0")
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 201


async def test_upload_rejected_when_client_version_is_none(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Old agent that never reported a version -> 426."""
    agent = await _seed_agent_with_version(db_session, None)
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 426
    body = r.json()
    assert body["detail"] == "Agent upgrade required"


async def test_upload_uses_default_when_tunable_missing(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """No tunable row in server_settings -> compiled default 0.5.0.
    Agent at 0.5.0 should pass."""
    agent = await _seed_agent_with_version(db_session, "0.5.0")
    # Do NOT insert a tunable row. Reset cache to force a DB read.
    from ingest_service.main import reset_min_version_cache

    reset_min_version_cache()

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 201


async def test_upload_uses_default_when_tunable_missing_rejects_old(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """No tunable row -> default 0.5.0. Agent at 0.4.0 should be rejected."""
    agent = await _seed_agent_with_version(db_session, "0.4.0")
    from ingest_service.main import reset_min_version_cache

    reset_min_version_cache()

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 426


async def test_upload_rejected_when_agent_version_unparseable(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Agent reports garbage version string -> 426."""
    agent = await _seed_agent_with_version(db_session, "not-a-version")
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 426


async def test_upload_handles_v_prefix(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Agent at v0.5.0 (with v prefix), min at 0.5.0 -> allowed."""
    agent = await _seed_agent_with_version(db_session, "v0.5.0")
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 201


async def test_upload_handles_prerelease_suffix(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Agent at 0.5.0-rc1, min at 0.5.0 -> allowed (pre-release suffix
    stripped; base version equals minimum)."""
    agent = await _seed_agent_with_version(db_session, "0.5.0-rc1")
    await _set_min_agent_version(db_session, "0.5.0")

    r = await _upload(client, agent["api_token"])
    assert r.status_code == 201


# -- Unit tests for _parse_version -----------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0.5.0", (0, 5, 0)),
        ("v1.2.3", (1, 2, 3)),
        ("0.5.0-rc1", (0, 5, 0)),
        ("v0.6.0-beta.2", (0, 6, 0)),
        ("10.20.30", (10, 20, 30)),
    ],
)
def test_parse_version(raw: str, expected: tuple[int, ...]) -> None:
    from ingest_service.main import _parse_version

    assert _parse_version(raw) == expected
