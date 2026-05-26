"""Shared HTTP helpers for internal-service client modules.

Centralises the ``httpx.AsyncClient`` lifecycle and error-classification
boilerplate that was copy-pasted across :mod:`analytics_client`,
:mod:`auth_client`, and :mod:`parser_client`.

Two helpers are provided:

* :func:`raw_request` — opens a short-lived ``AsyncClient``, injects an
  ``Authorization`` header when *token* is given, and wraps any
  :class:`httpx.HTTPError` in *error_cls*.  The raw
  :class:`httpx.Response` is returned so the caller can do its own
  status-code handling.

* :func:`request` — calls :func:`raw_request`, then applies the
  standard "401/403 → *forbidden_cls*; ≥ 400 → *error_cls*" checks that
  most endpoints share.  Functions with non-standard status-code logic
  should use :func:`raw_request` directly.

Both helpers also move the duplicated ``_parse_dt`` utility out of the
individual client modules.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Shared datetime parser (was duplicated in analytics_client + auth_client)
# ---------------------------------------------------------------------------


def parse_dt(raw: Any) -> datetime | None:
    """Parse an ISO-8601 datetime string, tolerating a trailing ``Z``."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# HTTP request helpers
# ---------------------------------------------------------------------------


async def raw_request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    timeout: float = 10.0,
    error_cls: type[Exception] = Exception,
    error_prefix: str = "",
    **kwargs: Any,
) -> httpx.Response:
    """Fire a single HTTP request and return the raw response.

    *error_cls* is the exception type raised when ``httpx.HTTPError``
    occurs (transport failure, DNS, timeout).  The caller is responsible
    for all status-code interpretation.

    Any extra *kwargs* are forwarded to ``client.request`` — use this
    for ``json=``, ``params=``, ``data=``, etc.
    """
    headers: dict[str, str] = dict(kwargs.pop("headers", None) or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Use the method-specific shortcut (client.get, client.post, ...)
            # rather than client.request so that existing test stubs that
            # monkeypatch individual verbs continue to work.
            verb = method.upper()
            if verb == "GET":
                return await client.get(url, headers=headers, **kwargs)
            if verb == "POST":
                return await client.post(url, headers=headers, **kwargs)
            if verb == "PUT":
                return await client.put(url, headers=headers, **kwargs)
            if verb == "PATCH":
                return await client.patch(url, headers=headers, **kwargs)
            if verb == "DELETE":
                return await client.delete(url, headers=headers, **kwargs)
            return await client.request(method, url, headers=headers, **kwargs)
    except httpx.HTTPError as exc:
        raise error_cls(f"{error_prefix}transport error: {exc}") from exc


async def request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    timeout: float = 10.0,
    error_cls: type[Exception] = Exception,
    forbidden_cls: type[Exception] = Exception,
    error_prefix: str = "",
    **kwargs: Any,
) -> httpx.Response:
    """Fire a request with standard status-code error handling.

    After obtaining the response via :func:`raw_request`:

    * 401 / 403 → raises *forbidden_cls*
    * any other ≥ 400 → raises *error_cls*

    If the endpoint has special handling for certain codes (404 → None,
    409 → error tuple, etc.) use :func:`raw_request` instead and handle
    them in the caller.
    """
    resp = await raw_request(
        method,
        url,
        token=token,
        timeout=timeout,
        error_cls=error_cls,
        error_prefix=error_prefix,
        **kwargs,
    )
    if resp.status_code in (401, 403):
        raise forbidden_cls(f"{error_prefix}returned {resp.status_code}")
    if resp.status_code >= 400:
        raise error_cls(f"{error_prefix}returned {resp.status_code}: {resp.text}")
    return resp
