"""Shared fixtures for parser tests.

Most parser tests are pure-Python unit tests that need no database.
A handful (notably the persistence-layer tests for issue #71) need a
real Postgres because the persistence code relies on PG-specific
features (partial unique indexes, ``ON CONFLICT``). Those tests gate
on the ``DA_TEST_DATABASE_URL`` env var:

* If unset, the fixtures are skipped — the rest of the suite still
  runs cleanly.
* If set, point at a writable Postgres. The fixture creates the
  ``parser`` and ``analytics`` schemas and the parser ORM tables
  from ``parser_service.models.Base.metadata``. Each test runs
  against a fresh schema (TRUNCATE between tests).

Local dev::

    docker run -d --rm --name parser-test-pg \\
      -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test \\
      -e POSTGRES_DB=parser_test \\
      -p 5489:5432 postgres:16-alpine

    DA_TEST_DATABASE_URL=postgresql+asyncpg://test:test@127.0.0.1:5489/parser_test \\
      PYTHONPATH=services/parser:. uv run pytest services/parser/tests/
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from parser_service.models import Base
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def _db_url() -> str | None:
    return os.environ.get("DA_TEST_DATABASE_URL")


_schema_initialized = False


@pytest_asyncio.fixture
async def parser_session() -> AsyncIterator[AsyncSession]:
    """Per-test isolated AsyncSession against a real Postgres.

    Engine is function-scoped to avoid the event-loop-mismatch trap
    asyncpg has with session-scoped fixtures; the per-test cost is a
    quick connect + TRUNCATE.
    """
    url = _db_url()
    if not url:
        pytest.skip("DA_TEST_DATABASE_URL not set — skipping DB-backed tests")

    engine = create_async_engine(url, future=True)
    global _schema_initialized
    try:
        if not _schema_initialized:
            async with engine.begin() as conn:
                await conn.execute(text("CREATE SCHEMA IF NOT EXISTS parser"))
                await conn.execute(text("CREATE SCHEMA IF NOT EXISTS analytics"))
                await conn.run_sync(Base.metadata.create_all)
                # analytics.card_game_stats is owned by the analytics
                # service (alembic 021) — but the cleanup script
                # references it explicitly because it has no FK to
                # parser.matches.id. Stub it so the script's DELETE
                # doesn't blow up the transaction.
                await conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS analytics.card_game_stats ("
                        "  id BIGSERIAL PRIMARY KEY,"
                        "  match_id UUID NOT NULL"
                        ")"
                    )
                )
            _schema_initialized = True

        async with engine.begin() as conn:
            await conn.execute(
                text("TRUNCATE parser.matches, parser.deck_compositions RESTART IDENTITY CASCADE")
            )
        sm = async_sessionmaker(engine, expire_on_commit=False)
        async with sm() as session:
            yield session
    finally:
        await engine.dispose()
