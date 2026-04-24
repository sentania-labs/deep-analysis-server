"""Raw file storage for ingest.

Content-addressed, sharded layout under a configurable root:

    <root>/<sha[0:2]>/<sha[2:4]>/<sha>.<ext>

Writes are atomic (write-to-temp, rename). Re-storing the same sha is
a no-op. Disk-full is surfaced as :class:`InsufficientStorageError`.
"""

from __future__ import annotations

import contextlib
import errno
import os
from collections.abc import AsyncIterator
from pathlib import Path

from ingest_service.schemas import ContentType

_EXT_BY_CONTENT_TYPE: dict[str, str] = {
    ContentType.MATCH_LOG.value: ".dat",
    ContentType.DECKLIST.value: ".xml",
    ContentType.UNKNOWN.value: ".bin",
}


class InsufficientStorageError(OSError):
    """Raised when the raw-file store is out of disk space."""


def extension_for(content_type: str, original_filename: str | None = None) -> str:
    """Return the file extension to use for a given content type.

    Falls back to sniffing a suffix from ``original_filename`` for the
    ``unknown`` type so we don't lose operator-visible hints.
    """
    ext = _EXT_BY_CONTENT_TYPE.get(content_type, ".bin")
    if content_type == ContentType.UNKNOWN.value and original_filename:
        suffix = Path(original_filename).suffix
        if suffix:
            return suffix
    return ext


def _shard_path(root: Path, sha256: str, extension: str) -> Path:
    return root / sha256[0:2] / sha256[2:4] / f"{sha256}{extension}"


def storage_path_for(sha256: str, extension: str) -> str:
    """Return the sharded relative path for a given sha.

    Used as the value of ``ingest.game_log_files.storage_path``. The
    absolute location is always ``<raw_root>/<storage_path>``.
    """
    return f"{sha256[0:2]}/{sha256[2:4]}/{sha256}{extension}"


async def store_file(
    content: bytes,
    sha256: str,
    extension: str,
    root: Path,
) -> Path:
    """Write ``content`` to the sharded location for ``sha256``.

    Idempotent: if the target already exists, returns its path without
    rewriting. Uses write-to-temp + atomic rename so concurrent
    uploads of the same file can't produce a half-written archive
    entry. Raises :class:`InsufficientStorageError` on ENOSPC.
    """
    target = _shard_path(root, sha256, extension)
    if target.exists():
        return target

    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.rename(tmp, target)
    except OSError as exc:
        # Best-effort cleanup of the tmp file; ignore if it's already gone.
        with contextlib.suppress(OSError):
            tmp.unlink()
        if exc.errno == errno.ENOSPC:
            raise InsufficientStorageError("disk full") from exc
        raise
    return target


async def open_file(
    sha256: str,
    extension: str,
    root: Path,
    chunk_size: int = 64 * 1024,
) -> AsyncIterator[bytes]:
    """Stream the content of a stored file in chunks."""
    path = _shard_path(root, sha256, extension)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                return
            yield chunk
