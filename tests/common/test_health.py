"""Unit tests for the common.health dependency-check helpers.

These tests mock DB sessions and Redis clients to verify the check
logic without any live infrastructure.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from common.health import (
    CheckResult,
    HealthReport,
    check_db,
    check_http,
    check_redis,
    evaluate,
)

# ---------------------------------------------------------------------------
# CheckResult / HealthReport unit tests
# ---------------------------------------------------------------------------


def test_health_report_all_ok() -> None:
    report = HealthReport(checks=[
        CheckResult(name="db", ok=True),
        CheckResult(name="redis", ok=True),
    ])
    assert report.healthy is True
    assert report.status == "ok"
    assert report.http_status == 200


def test_health_report_one_failed() -> None:
    report = HealthReport(checks=[
        CheckResult(name="db", ok=False, detail="error"),
        CheckResult(name="redis", ok=True),
    ])
    assert report.healthy is False
    assert report.status == "degraded"
    assert report.http_status == 503


def test_health_report_to_dict() -> None:
    report = HealthReport(checks=[
        CheckResult(name="db", ok=True),
        CheckResult(name="redis", ok=False, detail="error"),
    ])
    d = report.to_dict("auth")
    assert d == {
        "status": "degraded",
        "service": "auth",
        "db": "ok",
        "redis": "error",
    }


# ---------------------------------------------------------------------------
# check_db
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_db_success() -> None:
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()

    mock_sm = MagicMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_sm.return_value = mock_ctx

    result = await check_db(mock_sm)
    assert result.ok is True
    assert result.name == "db"
    assert result.detail == "ok"


@pytest.mark.asyncio
async def test_check_db_failure() -> None:
    mock_sm = MagicMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(side_effect=ConnectionRefusedError("connection refused"))
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_sm.return_value = mock_ctx

    result = await check_db(mock_sm)
    assert result.ok is False
    assert result.name == "db"
    assert result.detail == "error"


@pytest.mark.asyncio
async def test_check_db_timeout() -> None:
    """A DB that hangs beyond 2 seconds should be reported as failed."""

    async def _hang(*_args, **_kwargs):
        await asyncio.sleep(10)

    mock_session = AsyncMock()
    mock_session.execute = _hang

    mock_sm = MagicMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_sm.return_value = mock_ctx

    # Patch the timeout to be very short for test speed
    with patch("common.health._TIMEOUT_SECONDS", 0.05):
        result = await check_db(mock_sm)
    assert result.ok is False
    assert result.detail == "error"


# ---------------------------------------------------------------------------
# check_redis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_redis_success() -> None:
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)

    result = await check_redis(mock_redis)
    assert result.ok is True
    assert result.name == "redis"


@pytest.mark.asyncio
async def test_check_redis_failure() -> None:
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(side_effect=ConnectionError("redis down"))

    result = await check_redis(mock_redis)
    assert result.ok is False
    assert result.name == "redis"
    assert result.detail == "error"


@pytest.mark.asyncio
async def test_check_redis_timeout() -> None:
    """A Redis that hangs beyond 2 seconds should be reported as failed."""

    async def _hang(*_args, **_kwargs):
        await asyncio.sleep(10)

    mock_redis = AsyncMock()
    mock_redis.ping = _hang

    with patch("common.health._TIMEOUT_SECONDS", 0.05):
        result = await check_redis(mock_redis)
    assert result.ok is False
    assert result.detail == "error"


# ---------------------------------------------------------------------------
# check_http
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_http_success() -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("common.health.httpx.AsyncClient", return_value=mock_client):
        result = await check_http("http://auth:8000/healthz", "auth")
    assert result.ok is True
    assert result.name == "auth"


@pytest.mark.asyncio
async def test_check_http_failure() -> None:
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=ConnectionError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("common.health.httpx.AsyncClient", return_value=mock_client):
        result = await check_http("http://auth:8000/healthz", "auth")
    assert result.ok is False
    assert result.name == "auth"
    assert result.detail == "error"


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_all_healthy() -> None:
    async def _ok_db():
        return CheckResult(name="db", ok=True)

    async def _ok_redis():
        return CheckResult(name="redis", ok=True)

    report = await evaluate([_ok_db(), _ok_redis()])
    assert report.healthy is True
    assert report.http_status == 200
    assert len(report.checks) == 2


@pytest.mark.asyncio
async def test_evaluate_one_degraded() -> None:
    async def _ok_db():
        return CheckResult(name="db", ok=True)

    async def _bad_redis():
        return CheckResult(name="redis", ok=False, detail="error")

    report = await evaluate([_ok_db(), _bad_redis()])
    assert report.healthy is False
    assert report.http_status == 503
    d = report.to_dict("parser")
    assert d["status"] == "degraded"
    assert d["db"] == "ok"
    assert d["redis"] == "error"
