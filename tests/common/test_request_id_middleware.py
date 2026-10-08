"""Tests for the X-Request-ID ASGI middleware."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from collections.abc import AsyncIterator

import pytest
import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from starlette.types import Message, Receive, Scope, Send

from common.request_id import REQUEST_ID_HEADER, RequestIDMiddleware, get_request_id


def _configured_json_logger(buf: io.StringIO) -> structlog.typing.FilteringBoundLogger:
    """A logger that runs the exact processor chain ``configure_logging`` installs.

    Output goes to ``buf`` instead of stdout so the test can read the record.
    """
    from common.logging import configure_logging

    configure_logging("test")
    processors = structlog.get_config()["processors"]
    return structlog.wrap_logger(
        structlog.PrintLogger(file=buf),
        processors=processors,
        context_class=dict,
    )


@pytest.fixture()
def log_buffer() -> io.StringIO:
    return io.StringIO()


@pytest.fixture()
def app(log_buffer: io.StringIO) -> FastAPI:
    """A minimal FastAPI app with the RequestIDMiddleware attached."""
    logger = _configured_json_logger(log_buffer)

    _app = FastAPI()
    _app.add_middleware(RequestIDMiddleware)

    @_app.get("/ping")
    async def ping() -> dict[str, str]:
        # Read request_id from the stdlib context-var set by the middleware
        rid = get_request_id()
        logger.info("ping handled")
        return {"status": "ok", "request_id": rid or "unknown"}

    return _app


def _log_records(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


async def test_request_id_with_header(app: FastAPI, log_buffer: io.StringIO) -> None:
    """AC1: A request with X-Request-ID: abc produces a log record with
    request_id=abc and the response carries the same header."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/ping", headers={REQUEST_ID_HEADER: "abc"})
        assert resp.status_code == 200
        # Response carries the same header
        assert resp.headers.get(REQUEST_ID_HEADER) == "abc"
        # Context var was populated during the request
        body = resp.json()
        assert body["request_id"] == "abc"

    records = _log_records(log_buffer)
    assert len(records) == 1
    assert records[0]["event"] == "ping handled"
    assert records[0]["request_id"] == "abc"


async def test_request_id_without_header(app: FastAPI, log_buffer: io.StringIO) -> None:
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
        # Context var was populated during the request
        body = resp.json()
        assert body["request_id"] == request_id

    records = _log_records(log_buffer)
    assert len(records) == 1
    assert records[0]["request_id"] == request_id


def test_request_id_is_cleared_after_request(app: FastAPI) -> None:
    """The context var does not leak past the request that set it."""
    with TestClient(app) as client:
        client.get("/ping", headers={REQUEST_ID_HEADER: "abc"})
    assert get_request_id() is None


async def test_middleware_preserves_scope_client_and_headers() -> None:
    """Verify the middleware does not mutate scope["client"], the Request
    object, or any request headers. Auth rate limiters must see the same
    values they would see without this middleware."""
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

    sent: list[Message] = []

    async def fake_send(message: Message) -> None:
        sent.append(message)

    await mw(scope, receive, fake_send)

    # Verify the scope was NOT mutated and was passed by reference
    assert captured["scope_is_same"] is True, (
        "Middleware must pass the same scope dict to the inner app"
    )
    assert captured["scope_client"] == ("10.0.0.5", 54321), (
        "Middleware must not alter scope['client']"
    )
    assert b"x-forwarded-for" in [h[0] for h in captured["scope_headers"]]
    # The response start keeps its status and gains exactly one header.
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 200
    assert [h[0] for h in sent[0]["headers"]] == [b"content-type", b"x-request-id"]


async def test_lifespan_scope_is_forwarded_untouched() -> None:
    """Regression for the compose smoke failure: a non-http scope (lifespan,
    websocket) must reach the wrapped app with the original receive and send.

    The previous version returned early on non-http scopes without calling
    the app, so under uvicorn the lifespan handshake never reached FastAPI
    and no service ran its startup hook."""
    seen: dict = {}

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen["scope"] = scope
        seen["receive"] = receive
        seen["send"] = send

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        pass

    scope: Scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    await RequestIDMiddleware(inner)(scope, receive, send)

    assert seen["scope"] is scope
    assert seen["receive"] is receive
    assert seen["send"] is send


def test_fastapi_lifespan_runs_with_middleware_installed() -> None:
    """The lifespan scope travels through Starlette's middleware stack, so a
    FastAPI app with the middleware registered must still run its startup and
    shutdown hooks. This is the pattern every service uses."""
    events: list[str] = []

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        events.append("startup")
        yield
        events.append("shutdown")

    _app = FastAPI(lifespan=lifespan)
    _app.add_middleware(RequestIDMiddleware)

    @_app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    with TestClient(_app) as client:
        assert events == ["startup"]
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.headers.get(REQUEST_ID_HEADER)
    assert events == ["startup", "shutdown"]


async def test_auth_login_limiter_sees_distinct_clients_through_middleware() -> None:
    """Drive the real auth app through the middleware from two client
    addresses and check the login rate limiter keys them separately.

    The login route validates its JSON body after the rate-limit dependency
    has run, so an empty body answers 422 while still counting against the
    client's login budget. Ten requests from one address are allowed, the
    eleventh answers 429, and a second address is still at 422. The DB
    session dependency is overridden because the limiter runs before any
    query and no Postgres is available here."""
    from auth_service.db import get_session
    from auth_service.main import app as auth_app
    from auth_service.rate_limit import RULES, reset_rate_limiter

    async def _no_session() -> AsyncIterator[None]:
        yield None

    login_limit = RULES["login"].max_requests
    reset_rate_limiter()
    auth_app.dependency_overrides[get_session] = _no_session
    try:
        client_a = ("10.0.0.1", 40001)
        client_b = ("10.0.0.2", 40002)
        async with (
            AsyncClient(
                transport=ASGITransport(app=auth_app, client=client_a),
                base_url="http://auth",
            ) as a,
            AsyncClient(
                transport=ASGITransport(app=auth_app, client=client_b),
                base_url="http://auth",
            ) as b,
        ):
            for _ in range(login_limit):
                resp = await a.post("/auth/login", json={})
                assert resp.status_code == 422, resp.text
                assert resp.headers.get(REQUEST_ID_HEADER)
            resp = await a.post("/auth/login", json={})
            assert resp.status_code == 429, "client A should be over its login budget"
            resp = await b.post("/auth/login", json={})
            assert resp.status_code == 422, (
                "client B shares no budget with client A, so scope['client'] "
                "must have survived the middleware"
            )
    finally:
        auth_app.dependency_overrides.pop(get_session, None)
        reset_rate_limiter()


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
