"""Admin review verdicts survive every force-reparse scope."""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import pytest
from alembic.config import Config
from analytics_service.review_verdicts import set_match_review_verdict
from analytics_service.stats import _load_user_matches
from parser_service.models import Match, MatchReviewVerdict
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.persistence import persist_match
from parser_service.reparse import _delete_all_matches, _delete_matches_for_user
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alembic import command

REPO_ROOT = Path(__file__).resolve().parents[3]


def _parsed(raw_match_id: str) -> ParsedMatch:
    return ParsedMatch(
        raw_match_id=raw_match_id,
        format="Modern",
        players=["alice", "bob"],
        winner="alice",
        match_result="2-0",
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="alice"),
        ],
    )


async def _seed_agent_upload(
    session: AsyncSession,
    *,
    user_id: int,
    agent_id: uuid.UUID,
    sha256: str,
) -> None:
    """Create the minimum cross-schema rows used by agent scoping."""
    await session.execute(text("CREATE SCHEMA IF NOT EXISTS auth"))
    await session.execute(text("CREATE SCHEMA IF NOT EXISTS ingest"))
    await session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS auth.users (
                id INTEGER PRIMARY KEY,
                email VARCHAR(320) NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                role VARCHAR(32) NOT NULL DEFAULT 'user'
            )
            """
        )
    )
    await session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS auth.agent_registrations (
                id UUID PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
                machine_name VARCHAR(255) NOT NULL,
                api_token_hash VARCHAR(255) NOT NULL UNIQUE
            )
            """
        )
    )
    await session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS ingest.game_log_files (
                sha256 VARCHAR(64) PRIMARY KEY,
                size_bytes BIGINT NOT NULL,
                content_type VARCHAR(32) NOT NULL,
                storage_path VARCHAR(512) NOT NULL
            )
            """
        )
    )
    await session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS ingest.user_uploads (
                id BIGSERIAL PRIMARY KEY,
                sha256 VARCHAR(64) NOT NULL REFERENCES ingest.game_log_files(sha256),
                user_id INTEGER NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
                agent_registration_id UUID NOT NULL
                    REFERENCES auth.agent_registrations(id) ON DELETE CASCADE
            )
            """
        )
    )
    await session.execute(
        text(
            """
            INSERT INTO auth.users (id, email, password_hash)
            VALUES (:user_id, :email, 'test-only')
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"user_id": user_id, "email": f"force-reparse-{user_id}@example.test"},
    )
    await session.execute(
        text(
            """
            INSERT INTO auth.agent_registrations
                (id, user_id, machine_name, api_token_hash)
            VALUES (:agent_id, :user_id, 'test-agent', :token)
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "agent_id": agent_id,
            "user_id": user_id,
            "token": f"force-reparse-{agent_id}",
        },
    )
    await session.execute(
        text(
            """
            INSERT INTO ingest.game_log_files
                (sha256, size_bytes, content_type, storage_path)
            VALUES (:sha256, 1, 'match-log', :storage_path)
            ON CONFLICT (sha256) DO NOTHING
            """
        ),
        {"sha256": sha256, "storage_path": f"raw/{sha256}"},
    )
    await session.execute(
        text(
            """
            INSERT INTO ingest.user_uploads
                (sha256, user_id, agent_registration_id)
            VALUES (:sha256, :user_id, :agent_id)
            """
        ),
        {"sha256": sha256, "user_id": user_id, "agent_id": agent_id},
    )
    await session.commit()


@pytest.mark.parametrize("scope", ["user", "agent", "global"])
@pytest.mark.asyncio
async def test_rejected_match_survives_force_reparse_and_stays_hidden(
    parser_session: AsyncSession,
    scope: str,
) -> None:
    """Delete and rebuild changes the row ID but not the admin decision."""
    scope_number = {"user": 1, "agent": 2, "global": 3}[scope]
    user_id = 9100 + scope_number
    raw_match_id = f"stable-match-{scope}"
    sha256 = str(scope_number) * 64
    agent_id = uuid.uuid4()

    original = await persist_match(
        parser_session,
        _parsed(raw_match_id),
        sha256=sha256,
        user_id=user_id,
    )
    original_id = original.id

    owner_id = await set_match_review_verdict(
        parser_session,
        original_id,
        "rejected",
    )
    assert owner_id == user_id
    await parser_session.commit()

    if scope == "agent":
        await _seed_agent_upload(
            parser_session,
            user_id=user_id,
            agent_id=agent_id,
            sha256=sha256,
        )
        result = await _delete_matches_for_user(
            parser_session,
            user_id,
            None,
            None,
            agent_id=str(agent_id),
        )
    elif scope == "global":
        result = await _delete_all_matches(parser_session, None, None)
    else:
        result = await _delete_matches_for_user(
            parser_session,
            user_id,
            None,
            None,
            agent_id=None,
        )

    assert result.deleted_count == 1
    assert result.verdicts_carried_forward == 1
    assert (await parser_session.execute(select(Match))).scalar_one_or_none() is None
    assert (
        await parser_session.execute(select(MatchReviewVerdict))
    ).scalar_one().verdict == "rejected"

    rebuilt = await persist_match(
        parser_session,
        _parsed(raw_match_id),
        sha256=sha256,
        user_id=user_id,
    )
    assert rebuilt.id != original_id
    assert rebuilt.review_status == "rejected"

    visible_matches = await _load_user_matches(parser_session, user_id)
    assert visible_matches == []


@pytest.mark.parametrize(
    ("review_status", "stored_verdict"),
    [(None, "accepted"), ("pending_review", "pending_review"), ("rejected", "rejected")],
)
@pytest.mark.asyncio
async def test_every_admin_decision_is_written_to_durable_identity(
    parser_session: AsyncSession,
    review_status: str | None,
    stored_verdict: str,
) -> None:
    raw_match_id = f"admin-decision-{stored_verdict}"
    sha256 = {"accepted": "a", "pending_review": "b", "rejected": "c"}[stored_verdict] * 64
    match = await persist_match(
        parser_session,
        _parsed(raw_match_id),
        sha256=sha256,
        user_id=9300,
    )

    owner_id = await set_match_review_verdict(
        parser_session,
        match.id,
        review_status,
    )
    await parser_session.commit()

    assert owner_id == 9300
    stored = (await parser_session.execute(select(MatchReviewVerdict))).scalar_one()
    assert stored.identity_kind == "raw_match_id"
    assert stored.identity_value == raw_match_id
    assert stored.source_sha256 == sha256
    assert stored.verdict == stored_verdict


@pytest.mark.asyncio
async def test_sha_fallback_promotes_when_canonical_identity_appears(
    parser_session: AsyncSession,
) -> None:
    """A legacy verdict remains resolvable after later SHA changes."""
    user_id = 9400
    original_sha = "d" * 64
    later_sha = "e" * 64
    raw_match_id = "canonical-id-discovered-later"
    legacy = await persist_match(
        parser_session,
        _parsed("temporary-id"),
        sha256=original_sha,
        user_id=user_id,
    )
    await parser_session.execute(
        text("UPDATE parser.matches SET raw_match_id = NULL WHERE id = :match_id"),
        {"match_id": legacy.id},
    )
    await parser_session.commit()
    await set_match_review_verdict(parser_session, legacy.id, "rejected")
    await parser_session.commit()

    upgraded = await persist_match(
        parser_session,
        _parsed(raw_match_id),
        sha256=original_sha,
        user_id=user_id,
    )
    assert upgraded.id == legacy.id
    assert upgraded.review_status == "rejected"

    identities = set(
        (
            await parser_session.execute(
                select(
                    MatchReviewVerdict.identity_kind,
                    MatchReviewVerdict.identity_value,
                )
            )
        ).all()
    )
    assert ("source_sha256", original_sha) in identities
    assert ("raw_match_id", raw_match_id) in identities

    deletion = await _delete_matches_for_user(
        parser_session,
        user_id,
        None,
        None,
        agent_id=None,
    )
    assert deletion.verdicts_carried_forward == 1

    rebuilt = await persist_match(
        parser_session,
        _parsed(raw_match_id),
        sha256=later_sha,
        user_id=user_id,
    )
    assert rebuilt.id != legacy.id
    assert rebuilt.review_status == "rejected"
    assert await _load_user_matches(parser_session, user_id) == []


@pytest.mark.asyncio
async def test_reparse_waits_for_admin_verdict_then_reports_it(
    parser_session: AsyncSession,
) -> None:
    """A concurrent admin decision is included before delete commits."""
    user_id = 9500
    match = await persist_match(
        parser_session,
        _parsed("concurrent-reparse-verdict"),
        sha256="f" * 64,
        user_id=user_id,
    )
    assert parser_session.bind is not None
    sessions = async_sessionmaker(parser_session.bind, expire_on_commit=False)

    async with sessions() as admin_session, sessions() as reparse_session:
        owner_id = await set_match_review_verdict(admin_session, match.id, "rejected")
        assert owner_id == user_id

        delete_task = asyncio.create_task(
            _delete_matches_for_user(
                reparse_session,
                user_id,
                None,
                None,
                agent_id=None,
            )
        )
        await asyncio.sleep(0.05)
        assert not delete_task.done(), "reparse must wait for the admin row lock"

        await admin_session.commit()
        result = await delete_task

    assert result.deleted_count == 1
    assert result.verdicts_carried_forward == 1


@pytest.mark.asyncio
async def test_in_place_parse_waits_for_concurrent_admin_verdict(
    parser_session: AsyncSession,
) -> None:
    """A parser write cannot expose a match after an admin rejects it."""
    user_id = 9600
    parsed = _parsed("concurrent-persist-verdict")
    match = await persist_match(
        parser_session,
        parsed,
        sha256="1a" * 32,
        user_id=user_id,
    )
    assert parser_session.bind is not None
    sessions = async_sessionmaker(parser_session.bind, expire_on_commit=False)

    async with sessions() as admin_session, sessions() as persistence_session:
        owner_id = await set_match_review_verdict(admin_session, match.id, "rejected")
        assert owner_id == user_id

        persist_task = asyncio.create_task(
            persist_match(
                persistence_session,
                parsed,
                sha256="2b" * 32,
                user_id=user_id,
                review_status=None,
            )
        )
        await asyncio.sleep(0.05)
        assert not persist_task.done(), "parser must wait for the admin row lock"

        await admin_session.commit()
        reparsed = await persist_task

    assert reparsed.review_status == "rejected"
    assert await _load_user_matches(parser_session, user_id) == []


@pytest.mark.parametrize(
    ("review_status", "review_reason", "expected_status", "sha_digit"),
    [
        pytest.param(
            "pending_review",
            "No game winners resolved (1 game observed)",
            None,
            "7",
            id="automatic-hold",
        ),
        pytest.param(
            "pending_review",
            None,
            "pending_review",
            "8",
            id="admin-flagged-pending",
        ),
        pytest.param(
            "rejected",
            "admin rejected",
            "rejected",
            "9",
            id="admin-rejected",
        ),
    ],
)
def test_upgrade_distinguishes_admin_verdicts_from_automatic_holds(
    review_status: str,
    review_reason: str | None,
    expected_status: str | None,
    sha_digit: str,
) -> None:
    """Root migration keeps admin decisions but not automatic parser holds."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        pytest.skip("DATABASE_URL not set; skipping migration integration test")

    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    engine = create_engine(db_url, future=True)
    match_id = uuid.uuid4()
    sha256 = sha_digit * 64
    raw_match_id = f"pre-032-{sha_digit}-match"

    command.downgrade(cfg, "031")
    try:
        with engine.begin() as connection:
            connection.execute(text("TRUNCATE parser.matches RESTART IDENTITY CASCADE"))
            connection.execute(
                text(
                    """
                    INSERT INTO parser.matches
                        (id, sha256, user_id, raw_match_id, players,
                         game_count, review_status, review_reason)
                    VALUES
                        (:id, :sha256, 9200, :raw_match_id,
                         CAST('["alice", "bob"]' AS JSONB), 1,
                         :review_status, :review_reason)
                    """
                ),
                {
                    "id": match_id,
                    "sha256": sha256,
                    "raw_match_id": raw_match_id,
                    "review_status": review_status,
                    "review_reason": review_reason,
                },
            )

        command.upgrade(cfg, "head")
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT identity_kind, identity_value, source_sha256,
                           verdict, review_reason
                      FROM parser.match_review_verdicts
                     WHERE user_id = 9200
                    """
                )
            ).one_or_none()
        if expected_status is None:
            assert row is None
        else:
            assert row is not None
            assert tuple(row) == (
                "raw_match_id",
                raw_match_id,
                sha256,
                expected_status,
                review_reason,
            )

        async def complete_and_rebuild() -> None:
            async_engine = create_async_engine(
                make_url(db_url).set(drivername="postgresql+asyncpg")
            )
            sessions = async_sessionmaker(async_engine, expire_on_commit=False)
            try:
                async with sessions() as session:
                    completed = await persist_match(
                        session,
                        _parsed(raw_match_id),
                        sha256="ab" * 32,
                        user_id=9200,
                    )
                    assert completed.id == match_id
                    assert completed.review_status == expected_status
                    visible = await _load_user_matches(session, 9200)
                    assert len(visible) == (0 if expected_status else 1)

                    deletion = await _delete_matches_for_user(
                        session,
                        9200,
                        None,
                        None,
                        agent_id=None,
                    )
                    assert deletion.deleted_count == 1
                    assert deletion.verdicts_carried_forward == (1 if expected_status else 0)
                    rebuilt = await persist_match(
                        session,
                        _parsed(raw_match_id),
                        sha256="cd" * 32,
                        user_id=9200,
                    )
                    assert rebuilt.id != match_id
                    assert rebuilt.review_status == expected_status
                    visible = await _load_user_matches(session, 9200)
                    assert len(visible) == (0 if expected_status else 1)
            finally:
                await async_engine.dispose()

        asyncio.run(complete_and_rebuild())
    finally:
        command.upgrade(cfg, "head")
        engine.dispose()
