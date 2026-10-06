"""Tests for the X-Request-ID ASGI middleware."""

from __future__ import annotations

import uuid

import pytest
import structlog
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from common.request_id import REQUEST_ID_HEADER, RequestIDMiddleware


@pytest.fixture()
def app() -> FastAPI:
    """A minimal FastAPI app with the RequestIDMiddleware attached."""
    from common.logging import configure_logging

    configure_logging("test")

    _app = FastAPI()
    _app.add_middleware(RequestIDMiddleware)

    @_app.get("/ping")
    async def ping() -> dict[str, str]:
        # Read request_id from structlog context during the request
        ctx = structlog.contextvars.get_contextvars()
        rid = ctx.get("request_id")
        return {"status": "ok", "request_id": rid or "unknown"}

    return _app


async def test_request_id_with_header(app: FastAPI) -> None:
    """AC1: A request with X-Request-ID: abc produces a log record with
    request_id=abc and the response carries the same header."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/ping", headers={REQUEST_ID_HEADER: "abc"})
        assert resp.status_code == 200
        # Response carries the same header
        assert resp.headers.get(REQUEST_ID_HEADER) == "abc"
        # Structlog context was populated during the request
        body = resp.json()
        assert body["request_id"] == "abc"


async def test_request_id_without_header(app: FastAPI) -> None:
    """AC2: A request without the header gets a generated id that appears in
    the log and the response."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/ping")
        assert resp.status_code == 200
        request_id = resp.headers.get(REQUEST_ID_HEADER)
        assert request_id is not None
        # Should be a valid UUID4
        assert uuid.UUID(request_id, version=4)
        # Structlog context was populated during the request
        body = resp.json()
        assert body["request_id"] == request_id
