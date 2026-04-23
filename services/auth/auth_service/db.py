"""Async SQLAlchemy engine + session dependency."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from auth_service.settings import get_settings

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _async_url(url: str) -> str:
    # Alembic + psycopg use `postgresql+psycopg://...`; asyncpg needs its
    # own dialect. Accept both and normalize for the async engine.
    if url.startswith("postgresql+asyncpg://"):
        return url
    if url.startswith("postgresql+psycopg://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql+psycopg://")
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


def get_engine():
    global _engine, _sessionmaker
    if _engine is None:
        url = _async_url(get_settings().database_url)
        _engine = create_async_engine(url, future=True, pool_pre_ping=True)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    sm = get_sessionmaker()
    async with sm() as session:
        yield session


def reset_engine() -> None:
    """Test hook: clear cached engine/sessionmaker after env changes."""
    global _engine, _sessionmaker
    _engine = None
    _sessionmaker = None
