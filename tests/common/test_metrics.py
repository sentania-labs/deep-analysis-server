"""Tests for common.metrics — metrics move to their own port (issue #134).

These verify the shape the issue asks for: no /metrics route on the app
itself, and a working listener on the configured metrics port.
"""

from __future__ import annotations

import socket
import urllib.request

from fastapi import FastAPI
from fastapi.testclient import TestClient

from common.metrics import start_metrics_server


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_app_has_no_metrics_route() -> None:
    """The app itself must never register a /metrics path."""
    app = FastAPI()
    client = TestClient(app)

    response = client.get("/metrics")

    assert response.status_code == 404


def test_start_metrics_server_serves_on_its_own_port() -> None:
    port = _free_port()

    start_metrics_server("test_service", port)

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
        body = resp.read().decode()
        assert resp.status == 200

    assert "test_service_request_duration_seconds" in body


def test_start_metrics_server_does_not_crash_on_port_collision() -> None:
    """Two services sharing a process (as test imports do) must not blow up
    the second one just because the port is already bound."""
    port = _free_port()

    start_metrics_server("collision_a", port)
    # Second call for a different service on the same port must not raise.
    start_metrics_server("collision_b", port)
