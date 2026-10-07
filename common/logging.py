"""Structlog JSON logging configuration."""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

from common.request_id import _request_id_ctx


def _merge_request_id(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> Mapping[str, Any]:
    """Read X-Request-ID from stdlib contextvars and add it to the event dict.

    This custom processor is chained *before*
    ``structlog.contextvars.merge_contextvars`` so that the structlog-level
    context (which is bound once at startup via ``bind_contextvars(service=...)``
    on every logger instance) is still applied after request-scoped values
    are injected from the stdlib context-var set by ``RequestIDMiddleware``.
    """
    request_id = _request_id_ctx.get()
    if request_id is not None:
        event_dict["request_id"] = request_id
    return event_dict


def configure_logging(service_name: str, level: str = "INFO") -> None:
    """Configure structlog for JSON output to stdout. Idempotent."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )

    structlog.configure(
        processors=[
            _merge_request_id,
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    structlog.contextvars.bind_contextvars(service=service_name)
