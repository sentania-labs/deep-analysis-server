"""Read raw uploaded files from the object archive.

The ingest service writes each upload to the S3-compatible archive
under a content-addressed key (``<prefix>/<ab>/<cd>/<sha>``) and
records that key in ``ingest.game_log_files.storage_path``. The parser
derives the same key from the sha and reads it back through the shared
adapter, so the two services share no filesystem.

The key carries no extension, so there is no extension-fallback search
any more: one key, one object, one round trip.
"""

from __future__ import annotations

from common.storage import (
    ObjectNotFoundError,
    ObjectStore,
    object_key,
)


class RawFileNotFoundError(FileNotFoundError):
    """Raised when no archived object exists for a given sha256."""


class RawFileTooLargeError(OSError):
    """Raised when an archived object exceeds the configured in-memory ceiling."""


def raw_key(sha256: str, key_prefix: str = "raw") -> str:
    """Return the archive key for ``sha256``."""
    return object_key(sha256, key_prefix)


async def read_raw(
    store: ObjectStore,
    sha256: str,
    key_prefix: str = "raw",
    max_bytes: int | None = None,
) -> bytes:
    """Read an archived object. Refuses to buffer more than ``max_bytes``.

    A ``None`` ceiling means no limit. The consumer wires the
    configured ``parser_max_log_bytes`` so a single pathologically
    large upload cannot exhaust process memory; the size comes from a
    HEAD, so an oversized object is never transferred at all.

    Store-level failures (unreachable endpoint, auth rejected) raise
    :class:`common.storage.ObjectStorageError` and are bounded by the
    adapter's timeouts, so a storage outage fails fast instead of
    hanging the worker.
    """
    key = raw_key(sha256, key_prefix)
    try:
        if max_bytes is not None:
            info = await store.head(key)
            if info.size_bytes > max_bytes:
                raise RawFileTooLargeError(
                    f"raw object for sha {sha256} is {info.size_bytes} bytes; "
                    f"exceeds ceiling {max_bytes}"
                )
        return await store.get(key)
    except ObjectNotFoundError as exc:
        raise RawFileNotFoundError(f"no archived object for sha {sha256} at {key}") from exc
