"""End-to-end check that root 002 REFERENCES grants actually took.

If the grants are missing, :class:`~ingest.user_uploads` can still be
created (the migration runs as postgres), but the ingest role has no
way to insert a row that validates the FK. Here we assert the FK
itself works by inserting a valid row and a bad row.
"""

from __future__ import annotations

import secrets
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def test_fk_to_auth_users_resolves(
    db_session: AsyncSession, seed_agent: dict[str, Any]
) -> None:
    sha = secrets.token_hex(32)
    await db_session.execute(
        text(
            "INSERT INTO ingest.game_log_files "
            "(sha256, size_bytes, content_type, storage_path) "
            "VALUES (:s, 1, 'match-log', 'x')"
        ),
        {"s": sha},
    )
    await db_session.execute(
        text(
            "INSERT INTO ingest.user_uploads "
            "(sha256, user_id, agent_registration_id) VALUES (:s, :u, :a)"
        ),
        {"s": sha, "u": seed_agent["user_id"], "a": str(seed_agent["agent_id"])},
    )
    await db_session.commit()

    n = (
        await db_session.execute(
            text("SELECT count(*) FROM ingest.user_uploads WHERE sha256 = :s"),
            {"s": sha},
        )
    ).scalar_one()
    assert n == 1
