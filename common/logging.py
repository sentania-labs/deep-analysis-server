"""Structlog JSON logging configuration and the uvicorn access-line formatter."""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog
import uvicorn.logging

from common.request_id import _request_id_ctx

#: uvicorn's own access-line format, copied from ``uvicorn.config.LOGGING_CONFIG``
#: so the request id can be appended to the line that already ships.
UVICORN_ACCESS_FMT = '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'

#: The access line uvicorn emits plus the request id, so a proxy log line can
#: be matched to the service line for the same request (issue #182).
ACCESS_FMT = f"{UVICORN_ACCESS_FMT} request_id=%(request_id)s"


class RequestIdAccessFormatter(uvicorn.logging.AccessFormatter):
    """uvicorn's access formatter with the current ``X-Request-ID`` appended.

    The id comes from the context-var that ``RequestIDMiddleware`` sets, which
    is still bound while uvicorn writes the access line for that request,
    including the 500 for an unhandled exception. A
    request that produced no id (a non-http scope, or a line emitted outside
    the middleware) renders as ``-``.
    """

    def formatMessage(self, record: logging.LogRecord) -> str:
        record.__dict__["request_id"] = _request_id_ctx.get() or "-"
        return super().formatMessage(record)


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


def _patch_uvicorn_dict_config() -> None:
    """Point uvicorn's own default access formatter at our class.

    Covers a Config built *after* this module is imported (an object-style
    startup, or a script that imports the app first): ``dictConfig`` then
    builds the id-bearing formatter directly.
    """
    formatters = uvicorn.config.LOGGING_CONFIG.get("formatters", {})
    entry = formatters.get("access")
    if isinstance(entry, dict) and entry.get("()") in (
        uvicorn.logging.AccessFormatter,
        "uvicorn.logging.AccessFormatter",
    ):
        # ``LOGGING_CONFIG`` names the class as a dotted string; ``dictConfig``
        # accepts the class as well.
        entry["()"] = RequestIdAccessFormatter
        entry["fmt"] = ACCESS_FMT


def _install_access_formatter() -> None:
    """Give ``uvicorn.access`` the formatter that carries the request id.

    Covers a Config built *before* this module is imported, which is what the
    ``uvicorn`` CLI does: ``Config.__init__`` applies ``LOGGING_CONFIG`` with
    ``dictConfig``, then ``Config.load()`` imports the app module that calls
    ``configure_logging``. By then the logger already has its stdout handler,
    so only the formatter needs replacing. Under ``TestClient`` there is no
    ``Config`` at all, so the handler is created here.
    """
    _patch_uvicorn_dict_config()

    access = logging.getLogger("uvicorn.access")
    if not access.handlers:
        access.addHandler(logging.StreamHandler(sys.stdout))
        access.propagate = False
    for handler in access.handlers:
        existing = handler.formatter
        if isinstance(existing, RequestIdAccessFormatter):
            continue
        # Keep whatever a custom ``--log-config`` already chose, and add only
        # the request id to it.
        base = getattr(existing, "_fmt", None) or UVICORN_ACCESS_FMT
        handler.setFormatter(
            RequestIdAccessFormatter(
                fmt=f"{base} request_id=%(request_id)s",
                use_colors=getattr(existing, "use_colors", None),
            )
        )


def configure_logging(service_name: str, level: str = "INFO") -> None:
    """Configure structlog for JSON output to stdout. Idempotent."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )
    _install_access_formatter()

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
