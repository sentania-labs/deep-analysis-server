"""ASGI middleware that manages X-Request-ID across the request lifecycle.

Reads X-Request-ID from the incoming request headers, generates a UUID4 when
absent, binds it into the context-var context, and echoes it back on every
response so the full gateway->service chain is traceable.

This middleware depends only on stdlib ``contextvars`` and Starlette ASGI
primitives — it never imports structlog, sqlalchemy, or any other heavy
package so that services without a database (the web service) can use it
without triggering a ``greenlet`` import error.

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

import contextvars
import uuid

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "x-request-id"

#: Context-var that carries the request-id for the duration of each
#: ASGI request.  Set by :class:`RequestIDMiddleware`; read by any
#: downstream code (``http_helper`` requests-forwarding, custom
#: structlog processors, etc.).
_request_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_request_id_ctx", default=None
)


class RequestIDMiddleware:
    """ASGI middleware that manages X-Request-ID.

    * Reads X-Request-ID from request headers; generates a UUID4 when absent.
    * Binds the value into the stdlib context-var context.
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

        token = _request_id_ctx.set(request_id)
        try:
            await self.app(scope, receive, inner_send)
        finally:
            _request_id_ctx.reset(token)


def get_request_id() -> str | None:
    """Return the current X-Request-ID from the context-var, or None."""
    return _request_id_ctx.get()


def get_request_id_header() -> str | None:
    """Return the X-Request-ID header value (same value, different name).

    This is the public API that http_helper and other callers use to read
    the request-id from the current context.
    """
    return get_request_id()


def get_request_id_from_scope(scope: Scope) -> str | None:
    """Return the X-Request-ID from an ASGI scope headers, or None."""
    headers = Headers(scope=scope)
    return headers.get(REQUEST_ID_HEADER)
