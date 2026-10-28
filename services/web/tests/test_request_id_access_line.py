"""The request id must still be bound when uvicorn writes the access line.

uvicorn logs the access line from the ``send`` callable it hands the app, on
``http.response.start``. The web app wraps its routes in
``BaseHTTPMiddleware`` layers (CSRF, MOTD); a request-id context var bound
inside one of them is gone by the time that ``send`` runs (issue #182).
"""

from __future__ import annotations

from typing import Any

from common.request_id import _request_id_ctx


async def test_request_id_bound_when_response_starts() -> None:
    from web_service import main as _main

    seen: list[str | None] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            seen.append(_request_id_ctx.get())

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/static/does-not-exist",
        "raw_path": b"/static/does-not-exist",
        "query_string": b"",
        "headers": [(b"x-request-id", b"proxy-42"), (b"host", b"test")],
        "client": ("10.0.0.5", 54321),
        "server": ("test", 80),
    }

    await _main.app(scope, receive, send)

    assert seen == ["proxy-42"]
