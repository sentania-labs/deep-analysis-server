"""Tests for analytics_client retry behaviour on transient errors.

Verifies that ``classify_with_confidence`` retries on
:class:`httpx.ConnectError` and :class:`httpx.TimeoutException` but
does **not** retry on HTTP 4xx responses or other transport errors.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from parser_service.analytics_client import _MAX_RETRIES, classify_with_confidence

_ASYNC_CLIENT = "parser_service.analytics_client.httpx.AsyncClient"
_ASYNC_SLEEP = "parser_service.analytics_client.asyncio.sleep"


def _ok_response(
    archetype_id: uuid.UUID | None = None,
    confidence: float = 0.85,
) -> httpx.Response:
    """Build a synthetic 200 response with a valid classify payload."""
    aid = archetype_id or uuid.uuid4()
    return httpx.Response(
        200,
        json={"archetype_id": str(aid), "confidence": confidence},
        request=httpx.Request(
            "POST",
            "http://analytics:8000/analytics/archetypes/classify",
        ),
    )


def _400_response() -> httpx.Response:
    return httpx.Response(
        400,
        text="bad request",
        request=httpx.Request(
            "POST",
            "http://analytics:8000/analytics/archetypes/classify",
        ),
    )


# ---- Retry on ConnectError then succeed ----


@pytest.mark.asyncio
async def test_retries_on_connect_error_then_succeeds() -> None:
    """First attempt raises ConnectError, second succeeds."""
    expected_id = uuid.uuid4()
    ok = _ok_response(archetype_id=expected_id)

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        side_effect=[httpx.ConnectError("connection refused"), ok],
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(_ASYNC_CLIENT, return_value=mock_client),
        patch(_ASYNC_SLEEP, new_callable=AsyncMock) as mock_sleep,
    ):
        result = await classify_with_confidence(
            "http://analytics:8000",
            ["Lightning Bolt", "Mountain"],
        )

    assert result is not None
    assert result.archetype_id == expected_id
    assert mock_client.post.call_count == 2
    mock_sleep.assert_awaited_once()


# ---- Retry on TimeoutException then succeed ----


@pytest.mark.asyncio
async def test_retries_on_timeout_then_succeeds() -> None:
    """First attempt times out, second succeeds."""
    expected_id = uuid.uuid4()
    ok = _ok_response(archetype_id=expected_id)

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        side_effect=[httpx.TimeoutException("read timed out"), ok],
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(_ASYNC_CLIENT, return_value=mock_client),
        patch(_ASYNC_SLEEP, new_callable=AsyncMock),
    ):
        result = await classify_with_confidence(
            "http://analytics:8000",
            ["Counterspell"],
        )

    assert result is not None
    assert mock_client.post.call_count == 2


# ---- All retries exhausted ----


@pytest.mark.asyncio
async def test_returns_none_after_all_retries_exhausted() -> None:
    """Every attempt fails with ConnectError — returns None."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        side_effect=httpx.ConnectError("connection refused"),
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(_ASYNC_CLIENT, return_value=mock_client),
        patch(_ASYNC_SLEEP, new_callable=AsyncMock) as mock_sleep,
    ):
        result = await classify_with_confidence(
            "http://analytics:8000",
            ["Bolt"],
        )

    assert result is None
    assert mock_client.post.call_count == _MAX_RETRIES + 1
    assert mock_sleep.await_count == _MAX_RETRIES


# ---- No retry on 4xx ----


@pytest.mark.asyncio
async def test_no_retry_on_4xx() -> None:
    """HTTP 400 is not retried — returns None immediately."""
    bad = _400_response()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=bad)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(_ASYNC_CLIENT, return_value=mock_client),
        patch(_ASYNC_SLEEP, new_callable=AsyncMock) as mock_sleep,
    ):
        result = await classify_with_confidence(
            "http://analytics:8000",
            ["Bolt"],
        )

    assert result is None
    assert mock_client.post.call_count == 1
    mock_sleep.assert_not_awaited()


# ---- No retry on non-transient HTTPError ----


@pytest.mark.asyncio
async def test_no_retry_on_generic_http_error() -> None:
    """A non-transient HTTPError is not retried."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        side_effect=httpx.DecodingError("bad encoding"),
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(_ASYNC_CLIENT, return_value=mock_client),
        patch(_ASYNC_SLEEP, new_callable=AsyncMock) as mock_sleep,
    ):
        result = await classify_with_confidence(
            "http://analytics:8000",
            ["Bolt"],
        )

    assert result is None
    assert mock_client.post.call_count == 1
    mock_sleep.assert_not_awaited()


# ---- Empty base_url skips everything ----


@pytest.mark.asyncio
async def test_empty_base_url_returns_none() -> None:
    """An empty base_url short-circuits without any HTTP call."""
    result = await classify_with_confidence("", ["Bolt"])
    assert result is None


# ---- Success on first attempt ----


@pytest.mark.asyncio
async def test_no_retry_on_immediate_success() -> None:
    """When the first call succeeds, no retry delay occurs."""
    expected_id = uuid.uuid4()
    ok = _ok_response(archetype_id=expected_id)

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=ok)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(_ASYNC_CLIENT, return_value=mock_client),
        patch(_ASYNC_SLEEP, new_callable=AsyncMock) as mock_sleep,
    ):
        result = await classify_with_confidence(
            "http://analytics:8000",
            ["Bolt"],
        )

    assert result is not None
    assert result.archetype_id == expected_id
    assert mock_client.post.call_count == 1
    mock_sleep.assert_not_awaited()
