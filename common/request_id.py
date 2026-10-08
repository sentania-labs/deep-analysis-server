"""ASGI middleware that manages X-Request-ID across the request lifecycle.

Reads X-Request-ID from the incoming request headers, generates a UUID4 when
absent, binds it into the context-var context, and echoes it back on every
response so the full gateway->service chain is traceable.

This middleware depends only on stdlib ``contextvars`` and Starlette ASGI
primitives. It never imports structlog, sqlalchemy, or any other heavy
package so that services without a database (the web service) can use it
without triggering a ``greenlet`` import error.

Scope handling
--------------

Only ``http`` scopes are touched. Every other scope type, and in particular
``lifespan``, is forwarded to the wrapped app untouched: Starlette routes the
lifespan scope through the whole middleware stack, so a middleware that does
not forward it silently disables every service's startup hook (the auth
admin bootstrap, the metrics server, the analytics background loops).
Uvicorn's default ``--lifespan auto`` then logs "ASGI 'lifespan' protocol
appears unsupported" and keeps serving, which is exactly how the compose
smoke failed: no bootstrap admin was ever created, the smoke's login wait
loop got 401 ten times and 429 from the login rate limiter after that.

The ``scope`` dict itself is never copied or rewritten, so ``scope["client"]``
and the request headers reach downstream code (such as the auth login rate
limiter, which keys on the client address) exactly as the server set them.

Usage
-----

.. code-block:: python

    from fastapi import FastAPI
    from common.request_id import RequestIDMiddleware

    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
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
    * Forwards ``lifespan`` and any other non-http scope to the app untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # lifespan / websocket: nothing to correlate, but the app must
            # still see the scope or its startup and shutdown hooks never run.
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = headers.get(REQUEST_ID_HEADER)
        if not request_id:
            request_id = str(uuid.uuid4())

        async def inner_send(message: Message) -> None:
            if message["type"] != "http.response.start":
                await send(message)
                return
            # Add X-Request-ID to the response headers while keeping every
            # other field of the message (status, trailers, ...) intact.
            message_headers = list(message.get("headers", []))
            message_headers.append((b"x-request-id", request_id.encode("latin-1")))
            await send({**message, "headers": message_headers})

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
