"""Prometheus metrics for FastAPI services.

Provides:
- Per-service request duration histogram (registered by ``start_metrics_server``)
- DB query duration histogram via SQLAlchemy event hooks (``instrument_engine``)
- A metrics HTTP listener on its own port, separate from the app port
  (``start_metrics_server``), so the public app surface never carries a
  /metrics path.
"""

from __future__ import annotations

import logging
import time

from prometheus_client import Histogram, start_http_server
from sqlalchemy import event
from sqlalchemy.engine import Engine

_log = logging.getLogger("common.metrics")

_HISTOGRAMS: dict[str, Histogram] = {}
_DB_HISTOGRAM: Histogram | None = None


def get_request_histogram(service_name: str) -> Histogram:
    """Return (or create) per-service request-duration Histogram. Idempotent."""
    if service_name in _HISTOGRAMS:
        return _HISTOGRAMS[service_name]

    hist = Histogram(
        f"{service_name}_request_duration_seconds",
        f"Request duration for {service_name} in seconds",
        labelnames=("method", "path", "status_code"),
    )
    _HISTOGRAMS[service_name] = hist
    return hist


def get_db_query_histogram() -> Histogram:
    """Return (or create) DB query duration Histogram. Idempotent."""
    global _DB_HISTOGRAM
    if _DB_HISTOGRAM is not None:
        return _DB_HISTOGRAM
    _DB_HISTOGRAM = Histogram(
        "db_query_duration_seconds",
        "Database query duration in seconds",
        labelnames=("service",),
    )
    return _DB_HISTOGRAM


def instrument_engine(sync_engine: Engine, service_name: str) -> None:
    """Attach SQLAlchemy event hooks to time queries.

    Uses ``before_cursor_execute`` / ``after_cursor_execute`` events on
    the synchronous engine (which asyncpg also routes through). The
    timing is recorded in the ``db_query_duration_seconds`` histogram.
    """
    histogram = get_db_query_histogram()

    @event.listens_for(sync_engine, "before_cursor_execute")
    def _before_cursor_execute(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        conn._da_query_start = time.perf_counter()  # type: ignore[attr-defined]

    @event.listens_for(sync_engine, "after_cursor_execute")
    def _after_cursor_execute(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        start = getattr(conn, "_da_query_start", None)
        if start is not None:
            duration = time.perf_counter() - start
            histogram.labels(service=service_name).observe(duration)


def start_metrics_server(service_name: str, metrics_port: int) -> None:
    """Start the Prometheus metrics HTTP listener for this process.

    Serves on its own port, separate from the app port, so /metrics is
    never reachable through the app's public HTTP surface regardless of
    what a proxy in front of it does or does not route.

    Binds to 0.0.0.0 (not loopback) because it still needs to be reachable
    from elsewhere on the compose/cluster network for scraping; its safety
    comes from being off the public port, not from a restrictive bind.

    NOTE: this starts one HTTP server per process via a background thread.
    Every service today runs single-worker uvicorn, so one process is one
    metrics listener. If a service is ever run with multiple uvicorn
    workers, each worker would try to bind the same port and this needs to
    move to prometheus_client's multiprocess mode instead.
    """
    get_request_histogram(service_name)
    try:
        start_http_server(metrics_port, addr="0.0.0.0")
        _log.info("metrics server listening on 0.0.0.0:%d", metrics_port)
    except OSError:
        # Best-effort: a bound port here means either two services share a
        # process (test suites import multiple service `main` modules into
        # one interpreter) or a real port collision on the host. Either
        # way the app itself must keep starting; metrics being unreachable
        # is not a reason to fail request serving.
        _log.warning("metrics server could not bind 0.0.0.0:%d; already in use", metrics_port)
