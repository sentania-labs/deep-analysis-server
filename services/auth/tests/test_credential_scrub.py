"""Regression tests for password scrubbing on unhandled errors.

If a DB error escapes /auth/login or /auth/agent/register-with-credentials,
FastAPI/uvicorn's default unhandled-exception logging may dump the request
body — which contains a plaintext password. Both handlers wrap their body
in a try/except that catches non-HTTPException errors and re-raises a
sanitized 500 with `from None` so no chained exception (carrying the
request body in its frame locals) escapes.

These tests pin that contract: on a forced DB error, the response is 500,
the body does NOT echo "password", and no log line carries the plaintext
password value.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from auth_service import db as _db
from auth_service import main as _main


class _ExplodingSession:
    """Drop-in for AsyncSession that raises on the first ORM call.

    Matches enough of the AsyncSession surface that the dependency
    override resolves without TypeErrors — we don't expect any call to
    succeed.
    """

    async def execute(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated DB failure")

    def add(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated DB failure")

    async def commit(self) -> None:
        raise RuntimeError("simulated DB failure")

    async def refresh(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated DB failure")

    async def rollback(self) -> None:
        return None

    async def close(self) -> None:
        return None


async def _exploding_get_session() -> Any:
    yield _ExplodingSession()


_LEAKY_PASSWORD = "leaky-plaintext-password-xyz-2026"


@pytest.fixture
def _override_db() -> Any:
    _main.app.dependency_overrides[_db.get_session] = _exploding_get_session
    try:
        yield
    finally:
        _main.app.dependency_overrides.pop(_db.get_session, None)


@pytest.mark.asyncio
async def test_register_with_credentials_db_error_scrubs_password(
    client: Any,
    _override_db: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    r = await client.post(
        "/auth/agent/register-with-credentials",
        json={
            "email": "scrub-test@example.com",
            "password": _LEAKY_PASSWORD,
            "agent_name": "laptop-1",
            "client_version": "0.7.14",
        },
    )
    assert r.status_code == 500, r.text
    assert _LEAKY_PASSWORD not in r.text
    assert "password" not in r.json()["detail"]
    for record in caplog.records:
        # Both the formatted message and the raw extra dict could carry
        # a leak; check the rendered line which covers both surfaces.
        assert _LEAKY_PASSWORD not in record.getMessage()
        for value in record.__dict__.values():
            assert _LEAKY_PASSWORD not in repr(value)


@pytest.mark.asyncio
async def test_login_db_error_scrubs_password(
    client: Any,
    _override_db: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    r = await client.post(
        "/auth/login",
        json={"email": "scrub-test@example.com", "password": _LEAKY_PASSWORD},
    )
    assert r.status_code == 500, r.text
    assert _LEAKY_PASSWORD not in r.text
    assert "password" not in r.json()["detail"]
    for record in caplog.records:
        assert _LEAKY_PASSWORD not in record.getMessage()
        for value in record.__dict__.values():
            assert _LEAKY_PASSWORD not in repr(value)
