"""Shared dependency health-check helpers.

Every service's ``/healthz`` endpoint uses these to verify that its
backing stores (Postgres, Redis, the object archive) are actually
reachable, rather than unconditionally returning ``{"status": "ok"}``.

Each probe has a **2-second timeout** so a hung backend doesn't make
the health endpoint hang indefinitely.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from common.storage import ObjectStore

_log = logging.getLogger("common.health")

_TIMEOUT_SECONDS = 2.0


@dataclass
class CheckResult:
    """Result of a single dependency check."""

    name: str
    ok: bool
    detail: str = "ok"


@dataclass
class HealthReport:
    """Aggregate health report for a service."""

    checks: list[CheckResult] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def status(self) -> str:
        return "ok" if self.healthy else "degraded"

    @property
    def http_status(self) -> int:
        return 200 if self.healthy else 503

    def to_dict(self, service: str) -> dict[str, str]:
        result: dict[str, str] = {"status": self.status, "service": service}
        for c in self.checks:
            result[c.name] = c.detail
        return result


async def check_db(sessionmaker: async_sessionmaker[AsyncSession]) -> CheckResult:
    """Ping Postgres with ``SELECT 1``; 2-second timeout."""
    try:
        async with asyncio.timeout(_TIMEOUT_SECONDS):
            async with sessionmaker() as session:
                await session.execute(text("SELECT 1"))
        return CheckResult(name="db", ok=True)
    except Exception as exc:  # noqa: BLE001
        _log.warning("healthz db check failed: %s", exc)
        return CheckResult(name="db", ok=False, detail="error")


async def check_redis(redis_client: aioredis.Redis) -> CheckResult:
    """Ping Redis; 2-second timeout."""
    try:
        async with asyncio.timeout(_TIMEOUT_SECONDS):
            await redis_client.ping()  # type: ignore[misc]
        return CheckResult(name="redis", ok=True)
    except Exception as exc:  # noqa: BLE001
        _log.warning("healthz redis check failed: %s", exc)
        return CheckResult(name="redis", ok=False, detail="error")


async def check_http(
    url: str,
    service_name: str,
    *,
    label: str | None = None,
) -> CheckResult:
    """GET a URL and expect 200; 2-second timeout.

    Used by the web service to verify that upstream services (auth,
    analytics) are reachable.
    """
    check_label = label or service_name
    try:
        async with asyncio.timeout(_TIMEOUT_SECONDS):
            async with httpx.AsyncClient() as client:
                r = await client.get(url)
                if r.status_code == 200:
                    return CheckResult(name=check_label, ok=True)
                return CheckResult(name=check_label, ok=False, detail="error")
    except Exception as exc:  # noqa: BLE001
        _log.warning("healthz http check %s failed: %s", check_label, exc)
        return CheckResult(name=check_label, ok=False, detail="error")


async def evaluate(checks: list[Any]) -> HealthReport:
    """Run all checks concurrently and return an aggregate report.

    ``checks`` is a list of coroutines (from the ``check_*`` functions
    above). They execute concurrently via ``asyncio.gather``.
    """
    results = await asyncio.gather(*checks, return_exceptions=True)
    report = HealthReport()
    for r in results:
        if isinstance(r, CheckResult):
            report.checks.append(r)
        else:
            # A check raised unexpectedly — treat as failure.
            report.checks.append(CheckResult(name="unknown", ok=False, detail="error"))
    return report


async def check_object_store(store: ObjectStore) -> CheckResult:
    """Head the archive bucket; 2-second timeout.

    The failure this exists for: the archive backend goes away and the
    service keeps answering 200 on /healthz while every upload or
    parse silently fails. The probe uses the store's short-budget
    client, so it answers in about a second when the store is gone.
    """
    try:
        async with asyncio.timeout(_TIMEOUT_SECONDS):
            await store.ping()
        return CheckResult(name="object_store", ok=True)
    except Exception as exc:  # noqa: BLE001
        _log.warning("healthz object_store check failed: %s", exc)
        return CheckResult(name="object_store", ok=False, detail="error")
