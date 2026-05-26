"""Thin HTTP client over the analytics classify endpoint.

The parser calls ``POST /analytics/archetypes/classify`` after a match
is persisted to opportunistically tag the row with an archetype. The
endpoint is unauthenticated by design — the classifier is a stateless
utility and the parser holds no JWT of its own.

Failures (transport, HTTP non-2xx, malformed payload) are caller-
swallowed: classification is best-effort and must never fail the parse.

Transient connection errors (container restarts, brief network blips)
are retried up to ``_MAX_RETRIES`` times with a fixed delay between
attempts so that a momentary analytics-service outage does not
permanently lose the classification for affected matches.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass

import httpx

_log = logging.getLogger("parser.analytics_client")

# Retry parameters for transient connection errors.
_MAX_RETRIES: int = 2
_RETRY_DELAY_SECONDS: float = 2.0


@dataclass
class ClassifyResult:
    """Archetype classification result with confidence score."""

    archetype_id: uuid.UUID
    confidence: float


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
    result = await classify_with_confidence(base_url, card_names, timeout_seconds=timeout_seconds)
    return result.archetype_id if result else None


async def classify_with_confidence(
    base_url: str,
    card_names: Iterable[str],
    *,
    timeout_seconds: float = 5.0,
) -> ClassifyResult | None:
    """Call analytics' classify endpoint, return id + confidence.

    Returns ``None`` under the same conditions as :func:`classify`.

    Transient connection errors (:class:`httpx.ConnectError`,
    :class:`httpx.TimeoutException`) are retried up to
    ``_MAX_RETRIES`` times with a fixed delay.  Non-transient failures
    (HTTP 4xx/5xx, malformed response) are **not** retried.
    """
    if not base_url:
        return None
    payload = {"card_names": list(card_names)}
    resp = await _post_with_retry(base_url, payload, timeout_seconds=timeout_seconds)
    if resp is None:
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
        aid = uuid.UUID(str(raw_id))
    except ValueError:
        _log.warning("analytics classify returned malformed archetype_id=%r", raw_id)
        return None
    confidence = float(data.get("confidence", 0.0))
    return ClassifyResult(archetype_id=aid, confidence=confidence)


async def _post_with_retry(
    base_url: str,
    payload: dict[str, list[str]],
    *,
    timeout_seconds: float = 5.0,
) -> httpx.Response | None:
    """POST to the classify endpoint, retrying on transient errors.

    Retries only on :class:`httpx.ConnectError` and
    :class:`httpx.TimeoutException` — the kind of failures caused by a
    container restart or momentary network hiccup.  All other
    ``HTTPError`` subclasses bubble up immediately (the caller will
    still swallow them, but they won't delay the parse with pointless
    retries).
    """
    url = f"{base_url}/analytics/archetypes/classify"
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):  # 0, 1, 2 → three total attempts
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                return await client.post(url, json=payload)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES:
                _log.warning(
                    "analytics classify transient error (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1,
                    _MAX_RETRIES + 1,
                    _RETRY_DELAY_SECONDS,
                    exc,
                )
                await asyncio.sleep(_RETRY_DELAY_SECONDS)
            else:
                _log.exception(
                    "analytics classify failed after %d attempts url=%s",
                    _MAX_RETRIES + 1,
                    base_url,
                )
        except httpx.HTTPError:
            _log.exception("analytics classify transport error url=%s", base_url)
            return None
    # All retries exhausted — log was already emitted above.
    assert last_exc is not None  # guaranteed by the loop logic
    return None
