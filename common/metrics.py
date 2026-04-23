"""Prometheus metrics mixin for FastAPI services."""

from __future__ import annotations

from fastapi import FastAPI
from prometheus_client import CONTENT_TYPE_LATEST, Histogram, generate_latest
from starlette.requests import Request
from starlette.responses import Response

_HISTOGRAMS: dict[str, Histogram] = {}


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


def mount_metrics(app: FastAPI, service_name: str) -> None:
    """Register /metrics endpoint on the given FastAPI app."""
    get_request_histogram(service_name)

    async def metrics_endpoint(_: Request) -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.add_route("/metrics", metrics_endpoint, methods=["GET"], include_in_schema=False)
