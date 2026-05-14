"""Prometheus metrics mixin for FastAPI services.

Provides:
- Per-service request duration histogram (``mount_metrics``)
- DB query duration histogram via SQLAlchemy event hooks (``instrument_engine``)
"""

from __future__ import annotations

import time

from fastapi import FastAPI
from prometheus_client import CONTENT_TYPE_LATEST, Histogram, generate_latest
from sqlalchemy import event
from sqlalchemy.engine import Engine
from starlette.requests import Request
from starlette.responses import Response

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
        setattr(conn, "_da_query_start", time.perf_counter())

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


def mount_metrics(app: FastAPI, service_name: str) -> None:
    """Register /metrics endpoint on the given FastAPI app."""
    get_request_histogram(service_name)

    async def metrics_endpoint(_: Request) -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.add_route("/metrics", metrics_endpoint, methods=["GET"], include_in_schema=False)
