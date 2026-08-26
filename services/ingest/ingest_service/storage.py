"""Raw file storage for ingest.

Content is written to the S3-compatible object archive through the
shared adapter in :mod:`common.storage`. Objects are keyed by sha256:

    <prefix>/<sha[0:2]>/<sha[2:4]>/<sha>

There is no extension in the key. The content type lives in the
object's own metadata and in ``ingest.game_log_files.content_type``,
so the reader never has to guess at a suffix.

Re-storing the same sha is a no-op: the key is derived from the
content, so a key that exists already holds those bytes.
"""

from __future__ import annotations

from pathlib import Path

from common.storage import (
    DEFAULT_CONTENT_TYPE,
    ObjectInfo,
    ObjectStore,
    object_key,
)
from ingest_service.schemas import ContentType

# What we tell the object store each payload is. Match logs are MTGO
# ``.dat`` files (binary-ish), decklists and reference data are XML.
_MIME_BY_CONTENT_TYPE: dict[str, str] = {
    ContentType.MATCH_LOG.value: DEFAULT_CONTENT_TYPE,
    ContentType.DECKLIST.value: "application/xml",
    ContentType.REFERENCE_DATA.value: "application/xml",
    ContentType.UNKNOWN.value: DEFAULT_CONTENT_TYPE,
}

# Extensions the pre-S3 filesystem archive used, by content type. Only
# the backfill needs these: it has to find the old sharded files on the
# legacy volume before it can upload them.
_LEGACY_EXT_BY_CONTENT_TYPE: dict[str, str] = {
    ContentType.MATCH_LOG.value: ".dat",
    ContentType.DECKLIST.value: ".xml",
    ContentType.REFERENCE_DATA.value: ".xml",
    ContentType.UNKNOWN.value: ".bin",
}


def mime_for(content_type: str) -> str:
    """Return the MIME type recorded on the stored object."""
    return _MIME_BY_CONTENT_TYPE.get(content_type, DEFAULT_CONTENT_TYPE)


def legacy_extension_for(content_type: str, original_filename: str | None = None) -> str:
    """Return the extension the filesystem archive would have used.

    Backfill-only. Kept so the migration can locate files the old
    layout wrote; nothing on the write path uses it.
    """
    ext = _LEGACY_EXT_BY_CONTENT_TYPE.get(content_type, ".bin")
    if content_type == ContentType.UNKNOWN.value and original_filename:
        suffix = Path(original_filename).suffix
        if suffix:
            return suffix
    return ext


def storage_path_for(sha256: str, key_prefix: str = "raw") -> str:
    """Return the object key recorded in ``game_log_files.storage_path``."""
    return object_key(sha256, key_prefix)


async def store_file(
    store: ObjectStore,
    content: bytes,
    sha256: str,
    content_type: str,
    key_prefix: str = "raw",
) -> ObjectInfo:
    """Put ``content`` in the archive under its content-addressed key.

    Idempotent. Storage failures surface as
    :class:`common.storage.ObjectStorageError` subclasses, promptly:
    the adapter's client has bounded connect/read timeouts and a
    bounded retry count, so an unreachable store errors in seconds
    rather than blocking the request forever.
    """
    return await store.put(
        object_key(sha256, key_prefix),
        content,
        content_type=mime_for(content_type),
    )
