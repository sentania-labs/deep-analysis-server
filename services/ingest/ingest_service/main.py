"""Ingest service — upload endpoint + healthz."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.agent_auth import AuthenticatedAgent
from common.events import FILE_INGESTED, FileIngestedPayload
from common.logging import configure_logging
from common.metrics import start_metrics_server
from common.redis_client import EventPublisher, get_redis
from common.storage import (
    ObjectStorageError,
    ObjectStore,
    ObjectStoreFullError,
    get_object_store,
    reset_object_store,
)
from ingest_service import models as _models  # noqa: F401 — load Base.metadata
from ingest_service.db import get_session
from ingest_service.deps import get_current_agent
from ingest_service.schemas import AgentClassification, ContentType, UploadResponse
from ingest_service.settings import get_settings
from ingest_service.storage import storage_path_for, store_file

SERVICE_NAME = "ingest"
configure_logging(SERVICE_NAME)

_log = logging.getLogger("ingest.main")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    start_metrics_server(SERVICE_NAME, get_settings().metrics_port)
    yield


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Agent version gate — reject uploads from agents below min_agent_version
# ---------------------------------------------------------------------------

# Compiled fallback — must match auth_service.admin._STRING_TUNABLE_DEFAULTS.
_DEFAULT_MIN_AGENT_VERSION = "0.5.0"

# Cache the DB-backed tunable so every upload doesn't query server_settings.
_MIN_VERSION_CACHE_TTL = 60  # seconds
_cached_min_version: tuple[str, float] | None = None


def _parse_version(raw: str) -> tuple[int, ...]:
    """Parse a semver-ish string into an integer tuple for comparison.

    Strips an optional leading ``v`` and ignores any pre-release suffix
    (``-rc1``, ``-beta.2``, etc.).  Returns ``(major, minor, patch)``.
    """
    cleaned = raw.strip().lstrip("v")
    # Drop pre-release suffix
    cleaned = re.split(r"[+-]", cleaned, maxsplit=1)[0]
    return tuple(int(p) for p in cleaned.split("."))


async def _read_min_agent_version(db: AsyncSession) -> str:
    """Read ``min_agent_version`` from ``auth.server_settings`` with a
    60-second in-process cache.  Falls back to the compiled default
    when the row is absent (fresh install, migration not yet run)."""
    global _cached_min_version
    now = time.monotonic()
    if _cached_min_version is not None:
        val, ts = _cached_min_version
        if now - ts < _MIN_VERSION_CACHE_TTL:
            return val

    try:
        row = (
            await db.execute(
                text(
                    "SELECT value FROM auth.server_settings WHERE key = 'tunable:min_agent_version'"
                )
            )
        ).scalar_one_or_none()
    except Exception:  # noqa: BLE001 — graceful degradation
        _log.warning("failed to read min_agent_version tunable", exc_info=True)
        row = None

    result = (
        str(row)
        if row is not None and isinstance(row, str) and row.strip()
        else _DEFAULT_MIN_AGENT_VERSION
    )
    _cached_min_version = (result, now)
    return result


def reset_min_version_cache() -> None:
    """Test hook — clear the cached min_agent_version."""
    global _cached_min_version
    _cached_min_version = None


def _check_agent_version(agent: AuthenticatedAgent, min_version: str) -> JSONResponse | None:
    """Return a 426 JSONResponse if the agent is below *min_version*,
    or ``None`` if the agent is allowed through."""
    if agent.client_version is None:
        return JSONResponse(
            status_code=426,
            content={
                "detail": "Agent upgrade required",
                "min_version": min_version,
            },
        )
    try:
        min_ver = _parse_version(min_version)
    except (ValueError, IndexError):
        _log.error("unparseable min_agent_version tunable: %s — allowing upload", min_version)
        return None
    try:
        agent_ver = _parse_version(agent.client_version)
    except (ValueError, IndexError):
        return JSONResponse(
            status_code=426,
            content={
                "detail": "Agent upgrade required",
                "min_version": min_version,
            },
        )
    if agent_ver < min_ver:
        return JSONResponse(
            status_code=426,
            content={
                "detail": "Agent upgrade required",
                "min_version": min_version,
            },
        )
    return None


_publisher: EventPublisher | None = None


async def _get_publisher() -> EventPublisher:
    global _publisher
    if _publisher is None:
        client = await get_redis(get_settings().redis_url)
        _publisher = EventPublisher(client)
    return _publisher


def reset_publisher() -> None:
    """Test hook."""
    global _publisher
    _publisher = None


def get_store() -> ObjectStore:
    """The raw archive. Built once per process from settings."""
    return get_object_store(get_settings().s3_config())


def reset_store() -> None:
    """Test hook."""
    reset_object_store()


@app.get("/healthz")
@app.get("/ingest/healthz")
async def healthz() -> JSONResponse:
    from common.health import check_db, check_object_store, check_redis, evaluate
    from ingest_service.db import get_sessionmaker as _get_sm

    redis_client = await get_redis(get_settings().redis_url)
    report = await evaluate(
        [
            check_db(_get_sm()),
            check_redis(redis_client),
            # The archive is a hard dependency of every upload, so an
            # unreachable object store has to read as degraded rather
            # than letting the service accept traffic it cannot serve.
            check_object_store(get_store()),
        ]
    )
    return JSONResponse(
        content=report.to_dict(SERVICE_NAME),
        status_code=report.http_status,
    )


def _too_large() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
        detail={"error": "file_too_large"},
    )


def _bad_request(code: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": code},
    )


@app.post(
    "/ingest/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    original_filename: str | None = Form(default=None),
    content_type: ContentType = Form(default=ContentType.MATCH_LOG),
    file_mtime: float | None = Form(default=None),
    # Agent tail-scan verdict, optional by contract: agents older than
    # the field omit it, and an omitted (or empty) value behaves exactly
    # as it did before the field existed. A present-but-unrecognized
    # value 422s rather than being coerced.
    agent_classification: AgentClassification | None = Form(default=None),
    agent: AuthenticatedAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_session),
) -> UploadResponse:
    settings = get_settings()

    # --- Agent version gate ---
    min_ver = await _read_min_agent_version(db)
    version_rejection = _check_agent_version(agent, min_ver)
    if version_rejection is not None:
        return version_rejection

    # Cheap rejection before we buffer the body. Content-Length covers
    # the whole multipart envelope, not just the file part — but if
    # the envelope itself already exceeds the cap the file can't fit.
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > settings.ingest_max_file_bytes:
                raise _too_large()
        except ValueError:
            pass

    if file is None or file.filename is None:
        raise _bad_request("missing_file")

    content = await file.read()
    size = len(content)
    if size > settings.ingest_max_file_bytes:
        raise _too_large()

    sha = hashlib.sha256(content).hexdigest()
    storage_path = storage_path_for(sha, settings.s3_key_prefix)

    # Upsert the content-addressed row. RETURNING tells us whether this
    # was a fresh insert (first-time content) or a dedup hit.
    insert_res = await db.execute(
        text(
            "INSERT INTO ingest.game_log_files "
            "(sha256, size_bytes, content_type, storage_path) "
            "VALUES (:sha, :size, :ct, :sp) "
            "ON CONFLICT (sha256) DO NOTHING "
            "RETURNING sha256"
        ),
        {"sha": sha, "size": size, "ct": content_type.value, "sp": storage_path},
    )
    inserted = insert_res.first() is not None
    deduped = not inserted

    # Only write to the archive on first-time content; re-uploads are a
    # no-op (store_file is idempotent anyway, since the key is derived
    # from the content, but skipping the round-trip is cheap).
    if inserted:
        try:
            await store_file(
                get_store(),
                content,
                sha,
                content_type.value,
                key_prefix=settings.s3_key_prefix,
            )
        except ObjectStoreFullError as exc:
            # Roll back the db row so the archive + table stay in sync.
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail={"error": "insufficient_storage"},
            ) from exc
        except ObjectStorageError as exc:
            # Store unreachable or refusing writes. Fail fast and loudly
            # rather than committing a row whose object never landed.
            await db.rollback()
            _log.error("object store write failed sha=%s: %s", sha, exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "storage_unavailable"},
            ) from exc

    # Always record the per-user attribution row, even on dedup.
    now = datetime.now(UTC)
    upload_row = await db.execute(
        text(
            "INSERT INTO ingest.user_uploads "
            "(sha256, user_id, agent_registration_id, uploaded_at, original_filename, "
            "agent_classification) "
            "VALUES (:sha, :uid, :aid, :at, :fn, :cls) "
            "RETURNING id"
        ),
        {
            "sha": sha,
            "uid": agent.user_id,
            "aid": str(agent.agent_id),
            "at": now,
            "fn": original_filename,
            # NULL for agents that predate the field. The parser
            # backfill reads this column back on reparse, so the
            # verdict survives the event that carried it.
            "cls": agent_classification.value if agent_classification is not None else None,
        },
    )
    upload_id = int(upload_row.scalar_one())

    await db.commit()

    if inserted:
        payload: FileIngestedPayload = {
            "sha256": sha,
            "user_id": agent.user_id,
            "agent_registration_id": str(agent.agent_id),
            "uploaded_at": now.isoformat(),
            "content_type": content_type.value,
        }
        if file_mtime is not None:
            payload["file_mtime"] = file_mtime
        if agent_classification is not None:
            payload["agent_classification"] = agent_classification.value
        try:
            publisher = await _get_publisher()
            await publisher.publish(FILE_INGESTED, dict(payload))
        except Exception:  # noqa: BLE001 — event publish is best-effort
            _log.exception("file.ingested publish failed sha=%s", sha)

    return UploadResponse(
        sha256=sha,
        size_bytes=size,
        deduped=deduped,
        upload_id=upload_id,
    )
