"""Service-prefix routing convention.

Every HTTP route on a service must sit under a prefix the gateway
routes to that service. The ingest 404 blocker in v0.4.1 (POST
/upload instead of /ingest/upload) is exactly the bug class this
test catches.

Allowed paths per service:

* ``/<service>/*`` — the service's own namespace
* ``/healthz`` — infra probe (gateway routes per-service via
  ``/<service>/healthz``, but services still expose the bare form
  for direct probing)
* ``/metrics`` — Prometheus scrape endpoint

Both auth and web own ``/admin/*``: auth keeps its JSON admin API for
service-to-service calls (web → auth) and direct ops access on the
internal docker network; web serves the admin UI at the same prefix
through the gateway (W3.5-C, see ``gateway/Caddyfile``).

The web service owns the Caddy catch-all, so end-user-facing browser
routes (``/login``, ``/logout``, ``/dashboard``, ``/settings/*``,
``/profile/*``, ``/admin/*``) intentionally live at the top level —
they're user-typed URLs, not service-namespaced API routes.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

# Services that run as HTTP apps (parser is a worker-in-waiting; web is a UI
# shell that currently exposes only /healthz + /metrics).
_SERVICES: dict[str, tuple[str, ...]] = {
    "auth": ("/auth/", "/admin/"),
    "ingest": ("/ingest/",),
    "analytics": ("/analytics/",),
    "web": ("/web/",),
}

_INFRA_PATHS = frozenset({"/healthz", "/metrics"})

# Web-service browser routes that Caddy routes via the catch-all — they
# sit outside the /web/ namespace on purpose because they are URLs a
# human types or lands on, not service API paths.
_WEB_BROWSER_PATHS = frozenset(
    {
        "/login",
        "/logout",
        "/dashboard",
        "/settings/password",
        "/profile",
        "/profile/edit",
        "/profile/agents",
        "/profile/agents/{agent_id}/revoke",
        "/admin/users",
        "/admin/users/{user_id}/delete",
        "/admin/users/{user_id}/reset-password",
        "/admin/agents",
        "/admin/agents/{agent_id}/revoke",
        "/admin/settings",
        "/admin/settings/registration-mode",
    }
)


def _ensure_import_env() -> None:
    """Auth settings are lazy but importing the module still needs
    a few env vars present. Defaults are safe; nothing is ever
    connected to."""
    repo_root = Path(__file__).resolve().parents[1]
    os.environ.setdefault("DA_JWT_PRIVATE_KEY_PATH", str(repo_root / ".nonexistent-jwt-priv"))
    os.environ.setdefault("DA_JWT_PUBLIC_KEY_PATH", str(repo_root / ".nonexistent-jwt-pub"))
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://stub:stub@localhost/stub")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")


def _load_app(service: str) -> FastAPI:
    _ensure_import_env()
    module = __import__(f"{service}_service.main", fromlist=["app"])
    return module.app


@pytest.mark.parametrize("service", sorted(_SERVICES.keys()))
def test_all_routes_are_prefixed(service: str) -> None:
    app = _load_app(service)
    allowed_prefixes = _SERVICES[service]

    # Only validate developer-defined APIRoutes. FastAPI's auto-added
    # /openapi.json, /docs, /redoc, etc. are framework internals and land
    # as plain Starlette Routes, not APIRoutes.
    offenders: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if path in _INFRA_PATHS:
            continue
        if service == "web" and path in _WEB_BROWSER_PATHS:
            continue
        if any(path.startswith(p) for p in allowed_prefixes):
            continue
        offenders.append(path)

    assert not offenders, (
        f"service '{service}' has routes outside its allowed prefixes "
        f"{allowed_prefixes}: {offenders}"
    )
