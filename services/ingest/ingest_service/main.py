"""Ingest service — upload endpoint + healthz."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.agent_auth import AuthenticatedAgent
from common.events import FILE_INGESTED, FileIngestedPayload
from common.logging import configure_logging
from common.metrics import mount_metrics
from common.redis_client import EventPublisher, get_redis
from ingest_service import models as _models  # noqa: F401 — load Base.metadata
from ingest_service.db import get_session
from ingest_service.deps import get_current_agent
from ingest_service.schemas import ContentType, UploadResponse
from ingest_service.settings import get_settings
from ingest_service.storage import (
    InsufficientStorageError,
    extension_for,
    storage_path_for,
    store_file,
)

SERVICE_NAME = "ingest"
configure_logging(SERVICE_NAME)

_log = logging.getLogger("ingest.main")

app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}")
mount_metrics(app, SERVICE_NAME)


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


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


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
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    original_filename: str | None = Form(default=None),
    content_type: ContentType = Form(default=ContentType.MATCH_LOG),
    agent: AuthenticatedAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_session),
) -> UploadResponse:
    settings = get_settings()

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
    ext = extension_for(content_type.value, original_filename)
    storage_path = storage_path_for(sha, ext)

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

    # Only write to disk on first-time content; re-uploads are a no-op
    # on the raw archive (store_file is idempotent anyway, but skipping
    # the syscall round-trip is cheap).
    if inserted:
        try:
            await store_file(content, sha, ext, settings.ingest_raw_path)
        except InsufficientStorageError as exc:
            # Roll back the db row so the archive + table stay in sync.
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                detail={"error": "insufficient_storage"},
            ) from exc

    # Always record the per-user attribution row, even on dedup.
    now = datetime.now(UTC)
    upload_row = await db.execute(
        text(
            "INSERT INTO ingest.user_uploads "
            "(sha256, user_id, agent_registration_id, uploaded_at, original_filename) "
            "VALUES (:sha, :uid, :aid, :at, :fn) "
            "RETURNING id"
        ),
        {
            "sha": sha,
            "uid": agent.user_id,
            "aid": str(agent.agent_id),
            "at": now,
            "fn": original_filename,
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
