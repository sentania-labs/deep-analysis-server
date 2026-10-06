"""ASGI middleware that manages X-Request-ID across the request lifecycle.

Reads X-Request-ID from the incoming request headers, generates a UUID4 when
absent, binds it into the structlog context-var context, and echoes it back
on every response so the full gateway->service chain is traceable.

Usage
-----

.. code-block:: python

    from fastapi import FastAPI
    from common.request_id import RequestIDMiddleware

    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)

This is a Starlette ``ASGiHTTPRouter``-compatible middleware class.
"""

from __future__ import annotations

import uuid

import structlog
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "x-request-id"


class RequestIDMiddleware:
    """ASGI middleware that manages X-Request-ID.

    * Reads X-Request-ID from request headers; generates a UUID4 when absent.
    * Binds the value into the structlog context-var context.
    * Echoes X-Request-ID on the response header.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await receive  # type: ignore[misc]
            return

        headers = Headers(scope=scope)
        request_id = headers.get(REQUEST_ID_HEADER)
        if not request_id:
            request_id = str(uuid.uuid4())

        async def inner_send(message: Message) -> None:
            if message["type"] != "http.response.start":
                await send(message)
                return
            # Add X-Request-ID to the response headers without dropping
            # other fields (status, etc.) required by the ASGI spec.
            message_headers = list(message.get("headers", []))
            message_headers.append((b"x-request-id", request_id.encode("latin-1")))
            await send(
                {
                    "type": message["type"],
                    "status": message["status"],
                    "headers": message_headers,
                }
            )

        try:
            structlog.contextvars.bind_contextvars(request_id=request_id)
            await self.app(scope, receive, inner_send)
        finally:
            structlog.contextvars.clear_contextvars()


def get_request_id(scope: Scope) -> str | None:
    """Return the X-Request-ID from an ASGI scope, or None."""
    headers = Headers(scope=scope)
    return headers.get(REQUEST_ID_HEADER)
