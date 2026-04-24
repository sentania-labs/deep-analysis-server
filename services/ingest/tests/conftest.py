"""Ingest service test fixtures.

Requires a live Postgres + Redis. Runs the full migration stack:
root head (001 schemas/roles → 002 cross-schema grants) → auth head
→ ingest head.
"""

from __future__ import annotations

import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alembic import command

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_ALEMBIC_INI = REPO_ROOT / "alembic.ini"
AUTH_ALEMBIC_INI = REPO_ROOT / "services" / "auth" / "alembic.ini"
INGEST_ALEMBIC_INI = REPO_ROOT / "services" / "ingest" / "alembic.ini"

DEFAULT_DB_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/deep_analysis"


def _sync_url() -> str:
    url = os.environ.get("DATABASE_URL", DEFAULT_DB_URL)
    if url.startswith("postgresql+asyncpg://"):
        url = "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    return url


def _async_url(sync_url: str) -> str:
    if sync_url.startswith("postgresql+psycopg://"):
        return "postgresql+asyncpg://" + sync_url.removeprefix("postgresql+psycopg://")
    if sync_url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + sync_url.removeprefix("postgresql://")
    return sync_url


@pytest.fixture(scope="session", autouse=True)
def _env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, Path]]:
    out = tmp_path_factory.mktemp("jwt-keys")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = out / "jwt_private.pem"
    pub_path = out / "jwt_public.pem"
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    raw_dir = tmp_path_factory.mktemp("ingest-raw")

    os.environ["DA_JWT_PRIVATE_KEY_PATH"] = str(priv_path)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    os.environ["DA_DATABASE_URL"] = _async_url(_sync_url())
    os.environ["DA_INGEST_RAW_PATH"] = str(raw_dir)
    # Small cap so the 413 test doesn't need a giant payload.
    os.environ["DA_INGEST_MAX_FILE_BYTES"] = "1024"

    yield priv_path, pub_path


@pytest.fixture(scope="session")
def sync_db_url() -> str:
    return _sync_url()


@pytest.fixture(scope="session")
def async_db_url(sync_db_url: str) -> str:
    return _async_url(sync_db_url)


@pytest.fixture(scope="session")
def _migrate(_env: Any, sync_db_url: str) -> Iterator[None]:
    eng = create_engine(sync_db_url, future=True)
    try:
        root_cfg = Config(str(ROOT_ALEMBIC_INI))
        root_cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        root_cfg.set_main_option("sqlalchemy.url", sync_db_url)

        auth_cfg = Config(str(AUTH_ALEMBIC_INI))
        auth_cfg.set_main_option(
            "script_location", str(REPO_ROOT / "services" / "auth" / "alembic")
        )
        auth_cfg.set_main_option("sqlalchemy.url", sync_db_url)

        ingest_cfg = Config(str(INGEST_ALEMBIC_INI))
        ingest_cfg.set_main_option(
            "script_location", str(REPO_ROOT / "services" / "ingest" / "alembic")
        )
        ingest_cfg.set_main_option("sqlalchemy.url", sync_db_url)

        command.upgrade(root_cfg, "head")
        command.upgrade(auth_cfg, "head")
        command.upgrade(ingest_cfg, "head")
        yield
    finally:
        eng.dispose()


@pytest_asyncio.fixture
async def async_engine(async_db_url: str, _migrate: None) -> AsyncIterator[Any]:
    eng = create_async_engine(async_db_url, future=True)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture
async def _truncate(async_engine: Any) -> AsyncIterator[None]:
    sm = async_sessionmaker(async_engine, expire_on_commit=False)
    async with sm() as s:
        await s.execute(
            text(
                "TRUNCATE ingest.user_uploads, ingest.game_log_files, "
                "auth.agent_registrations, auth.sessions, auth.users "
                "RESTART IDENTITY CASCADE"
            )
        )
        await s.commit()
    yield


@pytest_asyncio.fixture
async def db_session(async_engine: Any, _truncate: None) -> AsyncIterator[AsyncSession]:
    sm = async_sessionmaker(async_engine, expire_on_commit=False)
    async with sm() as s:
        yield s


@pytest_asyncio.fixture
async def seed_agent(db_session: AsyncSession) -> dict[str, Any]:
    """Create a user + agent registration; return api_token + ids."""
    from common.token_utils import hash_api_token

    user_email = f"u-{uuid.uuid4().hex[:8]}@example.com"
    user_row = (
        await db_session.execute(
            text(
                "INSERT INTO auth.users (email, password_hash, role) "
                "VALUES (:e, :h, 'user') RETURNING id"
            ),
            {"e": user_email, "h": "x" * 64},
        )
    ).scalar_one()

    api_token = secrets.token_urlsafe(32)
    agent_row = (
        await db_session.execute(
            text(
                "INSERT INTO auth.agent_registrations "
                "(user_id, machine_name, api_token_hash, client_version) "
                "VALUES (:u, :m, :h, :v) RETURNING id"
            ),
            {
                "u": user_row,
                "m": "test-machine",
                "h": hash_api_token(api_token),
                "v": "0.4.0-test",
            },
        )
    ).scalar_one()
    await db_session.commit()

    return {
        "user_id": int(user_row),
        "agent_id": agent_row,
        "api_token": api_token,
    }


@pytest_asyncio.fixture
async def redis_client(_env: Any) -> AsyncIterator[Any]:
    from redis.asyncio import from_url as redis_from_url

    url = os.environ.get("DA_REDIS_URL", "redis://localhost:6379/0")
    client = redis_from_url(url)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


@pytest_asyncio.fixture
async def client(_truncate: None, redis_client: Any) -> AsyncIterator[Any]:
    from httpx import ASGITransport, AsyncClient
    from ingest_service import db as _db
    from ingest_service import main as _main
    from ingest_service import settings as _settings

    _settings.reset_settings()
    _db.reset_engine()
    _main.reset_publisher()

    transport = ASGITransport(app=_main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
