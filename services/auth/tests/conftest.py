"""Auth service test fixtures.

Requires a live Postgres. Defaults:
    DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/deep_analysis

A throwaway 2048-bit RSA keypair is generated once per test session and
written to a tmpdir; env vars ``DA_JWT_PRIVATE_KEY_PATH`` and
``DA_JWT_PUBLIC_KEY_PATH`` are pointed at it before the auth service is
imported.
"""

from __future__ import annotations

import os
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

DEFAULT_DB_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/deep_analysis"


def _sync_url() -> str:
    url = os.environ.get("DATABASE_URL", DEFAULT_DB_URL)
    # Force sync dialect for alembic.
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
def _keys(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, Path]]:
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

    os.environ["DA_JWT_PRIVATE_KEY_PATH"] = str(priv_path)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    os.environ["DA_DATABASE_URL"] = _async_url(_sync_url())

    yield priv_path, pub_path


@pytest.fixture(scope="session")
def sync_db_url() -> str:
    return _sync_url()


@pytest.fixture(scope="session")
def async_db_url(sync_db_url: str) -> str:
    return _async_url(sync_db_url)


@pytest.fixture(scope="session")
def _migrate(_keys: Any, sync_db_url: str) -> Iterator[None]:
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

        command.upgrade(root_cfg, "head")
        command.upgrade(auth_cfg, "head")
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
        # CASCADE follows ``server_settings.updated_by_user_id`` → users
        # FK and wipes that row too — reseed it after the truncate so
        # each test starts with the migration-seeded default.
        await s.execute(
            text(
                "TRUNCATE auth.invite_tokens, auth.agent_registrations, "
                "auth.sessions, auth.users RESTART IDENTITY CASCADE"
            )
        )
        await s.execute(
            text(
                "INSERT INTO auth.server_settings (key, value) "
                "VALUES ('registration_mode', '\"invite_only\"'::jsonb) "
                "ON CONFLICT (key) DO UPDATE SET "
                "    value = EXCLUDED.value, "
                "    updated_by_user_id = NULL, "
                "    updated_at = now()"
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
async def seed_user(db_session: AsyncSession) -> dict[str, Any]:
    """Create a fresh user with a known password; return its attributes."""
    from auth_service.models import User
    from auth_service.passwords import hash_password

    plaintext = "correct horse battery staple"
    user = User(
        email=f"user-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password(plaintext),
        role="user",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return {"id": user.id, "email": user.email, "password": plaintext, "role": user.role}


@pytest_asyncio.fixture
async def redis_client(_keys: Any) -> AsyncIterator[Any]:
    """Flush the test Redis DB around each test."""
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
    # Ensure caches pick up env from _keys fixture.
    from auth_service import db as _db
    from auth_service import deps as _deps
    from auth_service import jwt_issue as _jwt
    from auth_service import settings as _settings
    from httpx import ASGITransport, AsyncClient

    _settings._settings = None
    _db.reset_engine()
    _deps.reset_verifier()
    _jwt._issuer = None

    from auth_service import main as _main

    _main.reset_redis()

    transport = ASGITransport(app=_main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
