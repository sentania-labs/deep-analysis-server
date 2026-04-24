"""Model-level assertions: FK shapes and cascade behavior."""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def _insert_game_log(db: AsyncSession, sha: str) -> None:
    await db.execute(
        text(
            "INSERT INTO ingest.game_log_files "
            "(sha256, size_bytes, content_type, storage_path) "
            "VALUES (:s, 10, 'match-log', :p)"
        ),
        {"s": sha, "p": f"{sha[0:2]}/{sha[2:4]}/{sha}.dat"},
    )


async def test_user_uploads_cascade_on_user_delete(
    db_session: AsyncSession, seed_agent: dict[str, Any]
) -> None:
    sha = secrets.token_hex(32)
    await _insert_game_log(db_session, sha)
    await db_session.execute(
        text(
            "INSERT INTO ingest.user_uploads "
            "(sha256, user_id, agent_registration_id) VALUES (:s, :u, :a)"
        ),
        {"s": sha, "u": seed_agent["user_id"], "a": str(seed_agent["agent_id"])},
    )
    await db_session.commit()

    await db_session.execute(
        text("DELETE FROM auth.users WHERE id = :u"),
        {"u": seed_agent["user_id"]},
    )
    await db_session.commit()

    remaining = (
        await db_session.execute(
            text("SELECT count(*) FROM ingest.user_uploads WHERE sha256 = :s"),
            {"s": sha},
        )
    ).scalar_one()
    assert remaining == 0

    # game_log_files row survives — content is device/user-neutral.
    survived = (
        await db_session.execute(
            text("SELECT count(*) FROM ingest.game_log_files WHERE sha256 = :s"),
            {"s": sha},
        )
    ).scalar_one()
    assert survived == 1


async def test_game_log_survives_user_upload_delete(
    db_session: AsyncSession, seed_agent: dict[str, Any]
) -> None:
    sha = secrets.token_hex(32)
    await _insert_game_log(db_session, sha)
    await db_session.execute(
        text(
            "INSERT INTO ingest.user_uploads "
            "(sha256, user_id, agent_registration_id) VALUES (:s, :u, :a)"
        ),
        {"s": sha, "u": seed_agent["user_id"], "a": str(seed_agent["agent_id"])},
    )
    await db_session.commit()

    await db_session.execute(
        text("DELETE FROM ingest.user_uploads WHERE sha256 = :s"),
        {"s": sha},
    )
    await db_session.commit()

    survived = (
        await db_session.execute(
            text("SELECT count(*) FROM ingest.game_log_files WHERE sha256 = :s"),
            {"s": sha},
        )
    ).scalar_one()
    assert survived == 1


async def test_content_type_check(db_session: AsyncSession) -> None:
    sha = secrets.token_hex(32)
    try:
        await db_session.execute(
            text(
                "INSERT INTO ingest.game_log_files "
                "(sha256, size_bytes, content_type, storage_path) "
                "VALUES (:s, 10, 'bogus', 'x')"
            ),
            {"s": sha},
        )
        await db_session.commit()
        raise AssertionError("CHECK constraint should have blocked 'bogus'")
    except Exception:
        await db_session.rollback()


async def test_foreign_key_to_auth_users_enforced(
    db_session: AsyncSession, seed_agent: dict[str, Any]
) -> None:
    sha = secrets.token_hex(32)
    await _insert_game_log(db_session, sha)
    try:
        await db_session.execute(
            text(
                "INSERT INTO ingest.user_uploads "
                "(sha256, user_id, agent_registration_id) VALUES (:s, 999999, :a)"
            ),
            {"s": sha, "a": str(seed_agent["agent_id"])},
        )
        await db_session.commit()
        raise AssertionError("FK to auth.users should have rejected bogus user_id")
    except Exception:
        await db_session.rollback()


async def test_foreign_key_to_agent_registrations_enforced(
    db_session: AsyncSession, seed_agent: dict[str, Any]
) -> None:
    sha = secrets.token_hex(32)
    await _insert_game_log(db_session, sha)
    try:
        await db_session.execute(
            text(
                "INSERT INTO ingest.user_uploads "
                "(sha256, user_id, agent_registration_id) VALUES (:s, :u, :a)"
            ),
            {
                "s": sha,
                "u": seed_agent["user_id"],
                "a": str(uuid.uuid4()),
            },
        )
        await db_session.commit()
        raise AssertionError("FK to auth.agent_registrations should have rejected")
    except Exception:
        await db_session.rollback()
