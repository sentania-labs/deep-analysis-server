"""Tests for the parser /healthz + /parser/healthz endpoints.

Covers both the happy path (all deps healthy) and degraded states
(DB failure, Redis failure) via mocked check helpers.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from common.health import CheckResult, HealthReport


def _stub_env(repo_root: Path) -> None:
    os.environ.setdefault("DA_SERVICE_NAME", "parser")
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://stub:stub@localhost/stub")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    os.environ.setdefault("DA_JWT_PUBLIC_KEY_PATH", str(repo_root / ".nonexistent-jwt-pub"))
    # A closed port, so any real object-store probe fails fast instead
    # of waiting on DNS for the compose-default endpoint.
    os.environ.setdefault("DA_S3_ENDPOINT_URL", "http://127.0.0.1:1")


@pytest_asyncio.fixture
async def client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[AsyncClient]:
    repo_root = Path(__file__).resolve().parents[3]
    _stub_env(repo_root)

    from parser_service import main as _main
    from parser_service import settings as _settings

    _settings.reset_settings()
    _main.reset_consumer()
    _main.reset_store()

    async def _noop() -> None:
        return None

    monkeypatch.setattr(_main, "_start_consumer", _noop)
    monkeypatch.setattr(_main, "_stop_consumer", _noop)

    transport = ASGITransport(app=_main.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _healthy_report() -> HealthReport:
    return HealthReport(
        checks=[
            CheckResult(name="db", ok=True),
            CheckResult(name="redis", ok=True),
        ]
    )


def _db_down_report() -> HealthReport:
    return HealthReport(
        checks=[
            CheckResult(name="db", ok=False, detail="error"),
            CheckResult(name="redis", ok=True),
        ]
    )


def _redis_down_report() -> HealthReport:
    return HealthReport(
        checks=[
            CheckResult(name="db", ok=True),
            CheckResult(name="redis", ok=False, detail="error"),
        ]
    )


@pytest.mark.asyncio
async def test_healthz_all_healthy(client: AsyncClient) -> None:
    with patch("common.health.evaluate", new_callable=AsyncMock, return_value=_healthy_report()):
        r = await client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "parser"
    assert body["db"] == "ok"
    assert body["redis"] == "ok"


@pytest.mark.asyncio
async def test_parser_healthz_canonical(client: AsyncClient) -> None:
    with patch("common.health.evaluate", new_callable=AsyncMock, return_value=_healthy_report()):
        r = await client.get("/parser/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_healthz_db_failure(client: AsyncClient) -> None:
    with patch("common.health.evaluate", new_callable=AsyncMock, return_value=_db_down_report()):
        r = await client.get("/healthz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["db"] == "error"
    assert body["redis"] == "ok"


@pytest.mark.asyncio
async def test_healthz_redis_failure(client: AsyncClient) -> None:
    with patch("common.health.evaluate", new_callable=AsyncMock, return_value=_redis_down_report()):
        r = await client.get("/healthz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["db"] == "ok"
    assert body["redis"] == "error"


async def test_healthz_reports_object_store_when_unreachable(client: AsyncClient) -> None:
    """The real check path includes the archive, and answers quickly.

    No mocking here on purpose: the point of the check is that a
    service whose storage is gone stops claiming to be healthy.
    """
    import time

    started = time.monotonic()
    r = await client.get("/healthz")
    elapsed = time.monotonic() - started

    body = r.json()
    assert body["object_store"] == "error"
    assert r.status_code == 503
    assert elapsed < 10, f"healthz took {elapsed:.1f}s with storage unreachable"
