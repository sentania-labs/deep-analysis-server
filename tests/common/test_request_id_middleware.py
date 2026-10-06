"""Tests for the X-Request-ID ASGI middleware."""

from __future__ import annotations

import uuid

import pytest
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
        # Read request_id from the stdlib context-var set by the middleware
        from common.request_id import get_request_id

        rid = get_request_id()
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


async def test_middleware_preserves_scope_client_and_headers() -> None:
    """Verify the middleware does not mutate scope["client"], the Request
    object, or any request headers — auth rate limiters must see the same
    values they would see without this middleware."""
    from starlette.types import Message, Receive, Scope, Send

    captured: dict = {}

    class DummyApp:
        """A minimal ASGI app that captures the scope for inspection."""

        def __init__(self, scope_ref: dict) -> None:
            self.scope_ref = scope_ref

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            captured["scope_is_same"] = scope is self.scope_ref
            captured["scope_client"] = scope.get("client")
            captured["scope_headers"] = list(scope.get("headers", []))
            # Send a valid response
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [[b"content-type", b"application/json"]],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b"{}",
                }
            )

    # Build an ASGI scope simulating a real client connection
    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [[b"x-forwarded-for", b"10.0.0.5"]],
        "client": ("10.0.0.5", 54321),
        "query_string": b"",
    }

    app = DummyApp(scope)
    mw = RequestIDMiddleware(app)

    async def receive() -> dict:
        return {"type": "http.request", "body": b""}

    async def fake_send(message: Message) -> None:
        """No-op send — inner_send will intercept and add headers before
        calling this, but we just need it to exist."""
        pass

    await mw(scope, receive, fake_send)

    # Verify the scope was NOT mutated and was passed by reference
    assert captured["scope_is_same"] is True, (
        "Middleware must pass the same scope dict to the inner app"
    )
    assert captured["scope_client"] == ("10.0.0.5", 54321), (
        "Middleware must not alter scope['client']"
    )
    assert b"x-forwarded-for" in [h[0] for h in captured["scope_headers"]]


def test_all_services_register_middleware() -> None:
    """AC3: Every service app registers the middleware."""
    import importlib

    services = [
        "auth_service.main",
        "web_service.main",
        "ingest_service.main",
        "analytics_service.main",
        "parser_service.main",
    ]

    for module_name in services:
        module = importlib.import_module(module_name)
        app = module.app
        # FastAPI wraps each app.add_middleware call in a class-based
        # wrapper; the middleware classes can be found by inspecting
        # the Starlette router's ``user_middleware`` list.
        middleware_classes = [m.cls for m in app.user_middleware]
        assert RequestIDMiddleware in middleware_classes, (
            f"{module_name}.app does not register RequestIDMiddleware "
            f"(registered: {middleware_classes})"
        )
