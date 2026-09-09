"""Thin HTTP client over the internal ingest service.

The web service calls ingest directly over the backend compose network
(``http://ingest:8000``) rather than looping through the Caddy gateway,
the same contract as the auth, analytics and parser clients.

Only the operator surface lives here. Uploads go agent-to-ingest and
never pass through the web service.
"""

from __future__ import annotations

from typing import Any

from web_service.http_helper import parse_dt as _parse_dt
from web_service.http_helper import raw_request, request


class IngestClientError(Exception):
    """Ingest call failed for transport, 5xx, or unexpected non-2xx."""


class IngestForbidden(Exception):
    """Ingest rejected the request as 401/403."""


class IngestBusy(Exception):
    """Ingest refused to start a job because one is already running."""


_ERR = {"error_cls": IngestClientError, "forbidden_cls": IngestForbidden}
_ERR_RAW = {"error_cls": IngestClientError}

_COUNTS = (
    "expected",
    "processed",
    "remaining",
    "uploaded",
    "already_present",
    "missing_source",
    "hash_mismatch",
    "failed",
    "verified",
    "verify_errors",
    "bytes_uploaded",
)


async def admin_get_raw_backfill(base_url: str, token: str) -> dict[str, Any]:
    """Progress and verdict of the legacy raw-archive migration."""
    resp = await request(
        "GET",
        f"{base_url}/ingest/admin/raw-backfill",
        token=token,
        error_prefix="ingest GET /ingest/admin/raw-backfill ",
        **_ERR,
    )
    payload = resp.json()
    parsed: dict[str, Any] = {
        "status": str(payload.get("status") or "unknown"),
        "enabled": bool(payload.get("enabled")),
        "source_root": payload.get("source_root"),
        "source_available": bool(payload.get("source_available")),
        "last_error": payload.get("last_error"),
        "is_running": bool(payload.get("is_running")),
        "running_since": _parse_dt(payload.get("running_since")),
        "started_at": _parse_dt(payload.get("started_at")),
        "updated_at": _parse_dt(payload.get("updated_at")),
        "completed_at": _parse_dt(payload.get("completed_at")),
    }
    for key in _COUNTS:
        parsed[key] = int(payload.get(key) or 0)
    expected = parsed["expected"]
    parsed["percent"] = round(100.0 * parsed["processed"] / expected, 1) if expected else 100.0
    return parsed


async def admin_run_raw_backfill(base_url: str, token: str) -> None:
    """Trigger the migration now. Raises ``IngestBusy`` on a 409."""
    resp = await raw_request(
        "POST",
        f"{base_url}/ingest/admin/raw-backfill/run",
        token=token,
        timeout=15.0,
        error_prefix="ingest POST /ingest/admin/raw-backfill/run ",
        **_ERR_RAW,
    )
    if resp.status_code in (401, 403):
        raise IngestForbidden(f"ingest raw-backfill run returned {resp.status_code}")
    if resp.status_code == 409:
        raise IngestBusy("a raw archive migration is already running")
    if resp.status_code >= 400:
        raise IngestClientError(f"ingest raw-backfill run returned {resp.status_code}: {resp.text}")
