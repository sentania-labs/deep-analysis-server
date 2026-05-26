"""CSRF protection — double-submit cookie pattern.

Every GET response sets a ``da_csrf`` cookie (if absent) containing a
random token. Every POST form must include a hidden ``csrf_token``
field whose value matches the cookie. Mismatches produce a 403.

Exempt paths (healthz, metrics, static) are skipped entirely.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import parse_qs

from fastapi import Request, Response
from fastapi.responses import HTMLResponse

_log = logging.getLogger("web.csrf")

CSRF_COOKIE_NAME = "da_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_TOKEN_BYTES = 32

# Paths that never carry session cookies / are not browser-form targets.
_EXEMPT_PREFIXES = (
    "/static",
    "/healthz",
    "/web/healthz",
    "/metrics",
)


def _is_exempt(path: str) -> bool:
    """Return True if the path is exempt from CSRF checks."""
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _EXEMPT_PREFIXES)


def _generate_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def _forbidden_response() -> Response:
    return HTMLResponse(
        content=(
            "<!doctype html><html><head><title>403 Forbidden</title></head>"
            "<body><h1>403 Forbidden</h1>"
            "<p>CSRF validation failed. Please go back and try again.</p>"
            "</body></html>"
        ),
        status_code=403,
    )


def _extract_csrf_from_body(body: bytes, content_type: str | None) -> str | None:
    """Extract the csrf_token from a URL-encoded or multipart form body.

    Only handles ``application/x-www-form-urlencoded`` (the default for
    HTML ``<form>``). Multipart bodies are rare for browser forms in this
    app, but we do a best-effort search for the field name in the raw
    bytes.
    """
    if not body:
        return None

    if content_type and "application/x-www-form-urlencoded" in content_type:
        try:
            parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            values = parsed.get(CSRF_FORM_FIELD)
            if values:
                return values[0]
        except Exception:  # noqa: BLE001
            pass
        return None

    if content_type and "multipart/form-data" in content_type:
        # Best-effort: search for the field in the raw body.
        # This handles the common case where the field is a simple text value.
        marker = f'name="{CSRF_FORM_FIELD}"'.encode()
        idx = body.find(marker)
        if idx == -1:
            return None
        # The value follows after two CRLFs.
        rest = body[idx + len(marker) :]
        sep = rest.find(b"\r\n\r\n")
        if sep == -1:
            return None
        after = rest[sep + 4 :]
        end = after.find(b"\r\n")
        if end == -1:
            return None
        return after[:end].decode("utf-8", errors="replace").strip()

    return None


async def csrf_middleware(request: Request, call_next: Any) -> Response:
    """ASGI middleware that enforces the double-submit cookie pattern.

    - GET/HEAD/OPTIONS: ensure the ``da_csrf`` cookie exists (set if
      missing) and stash the token on ``request.state.csrf_token`` so
      templates can render the hidden field.
    - POST/PUT/PATCH/DELETE: compare the cookie value against the
      ``csrf_token`` form field. Return 403 on mismatch.

    The body is read once and cached so the downstream route handler
    can still access it via ``Form()`` parameters.
    """
    path = request.url.path

    if _is_exempt(path):
        return await call_next(request)

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)

    if request.method in ("GET", "HEAD", "OPTIONS"):
        # Ensure a token exists for template rendering.
        token = cookie_token or _generate_token()
        request.state.csrf_token = token
        response = await call_next(request)
        if not cookie_token:
            # First visit or cookie expired — set it.
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=token,
                httponly=False,  # JS may need to read it
                secure=True,
                samesite="lax",
                path="/",
            )
        return response

    # State-mutating methods — validate.
    if not cookie_token:
        _log.warning("csrf.missing_cookie path=%s", path)
        return _forbidden_response()

    # Read the raw body and cache it so the downstream handler can
    # still consume it via Form().
    body = await request.body()
    content_type = request.headers.get("content-type")

    form_token = _extract_csrf_from_body(body, content_type)

    if not form_token or form_token != cookie_token:
        _log.warning(
            "csrf.mismatch path=%s has_form_token=%s",
            path,
            form_token is not None,
        )
        return _forbidden_response()

    # Valid — stash token for any template that might render on this
    # POST (e.g. inline validation errors re-rendering the form).
    request.state.csrf_token = cookie_token
    response = await call_next(request)
    return response
