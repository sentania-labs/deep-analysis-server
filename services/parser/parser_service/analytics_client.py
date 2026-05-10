"""Thin HTTP client over the analytics classify endpoint.

The parser calls ``POST /analytics/archetypes/classify`` after a match
is persisted to opportunistically tag the row with an archetype. The
endpoint is unauthenticated by design — the classifier is a stateless
utility and the parser holds no JWT of its own.

Failures (transport, HTTP non-2xx, malformed payload) are caller-
swallowed: classification is best-effort and must never fail the parse.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable

import httpx

_log = logging.getLogger("parser.analytics_client")


async def classify(
    base_url: str,
    card_names: Iterable[str],
    *,
    timeout_seconds: float = 5.0,
) -> uuid.UUID | None:
    """Call analytics' classify endpoint, return the matched archetype id.

    Returns ``None`` if:
    - ``base_url`` is empty (classify disabled in this environment),
    - the analytics call fails for any reason (network, 5xx, bad JSON),
    - or the classifier returned no archetype.
    """
    if not base_url:
        return None
    payload = {"card_names": list(card_names)}
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            resp = await client.post(
                f"{base_url}/analytics/archetypes/classify",
                json=payload,
            )
    except httpx.HTTPError:
        _log.exception("analytics classify transport error url=%s", base_url)
        return None
    if resp.status_code >= 400:
        _log.warning(
            "analytics classify returned %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None
    try:
        data = resp.json()
    except ValueError:
        _log.warning("analytics classify returned non-JSON body")
        return None
    raw_id = data.get("archetype_id")
    if not raw_id:
        return None
    try:
        return uuid.UUID(str(raw_id))
    except ValueError:
        _log.warning("analytics classify returned malformed archetype_id=%r", raw_id)
        return None
