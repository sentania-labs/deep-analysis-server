"""Async SQLAlchemy engine + session factory for analytics."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from analytics_service.settings import get_settings
from common.metrics import instrument_engine

_log = logging.getLogger("analytics.db")

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _async_url(url: str) -> str:
    if url.startswith("postgresql+asyncpg://"):
        return url
    if url.startswith("postgresql+psycopg://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql+psycopg://")
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        url = _async_url(get_settings().database_url)
        _engine = create_async_engine(url, future=True, pool_pre_ping=True)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
        # Instrument the underlying sync engine for query timing metrics
        try:
            instrument_engine(_engine.sync_engine, "analytics")
        except Exception:  # noqa: BLE001
            _log.warning("failed to instrument DB engine for metrics", exc_info=True)
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
    global _engine, _sessionmaker
    _engine = None
    _sessionmaker = None
