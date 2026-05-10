"""Smoke test for the parser /healthz + /parser/healthz endpoints.

The parser app starts a Redis consumer task on lifespan startup;
the test patches the start hook to a no-op so this stays a pure HTTP
smoke test (no live Redis or Postgres required).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


def _stub_env(repo_root: Path) -> None:
    os.environ.setdefault("DA_SERVICE_NAME", "parser")
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://stub:stub@localhost/stub")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    os.environ.setdefault("DA_JWT_PUBLIC_KEY_PATH", str(repo_root / ".nonexistent-jwt-pub"))
    os.environ.setdefault("DA_PARSER_RAW_PATH", str(repo_root / ".nonexistent-raw"))


@pytest_asyncio.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    repo_root = Path(__file__).resolve().parents[3]
    _stub_env(repo_root)

    from parser_service import main as _main
    from parser_service import settings as _settings

    _settings.reset_settings()
    _main.reset_consumer()

    async def _noop() -> None:
        return None

    # Skip the live Redis/Postgres bring-up; just run lifespan with stubs
    # so the FastAPI app boots cleanly.
    monkeypatch.setattr(_main, "_start_consumer", _noop)
    monkeypatch.setattr(_main, "_stop_consumer", _noop)

    transport = ASGITransport(app=_main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_healthz_alias(client: AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "parser"}


@pytest.mark.asyncio
async def test_parser_healthz_canonical(client: AsyncClient) -> None:
    r = await client.get("/parser/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "parser"}
