"""Parser-side archive reads go through the object store adapter."""

from __future__ import annotations

import pytest
from parser_service.storage import (
    RawFileNotFoundError,
    RawFileTooLargeError,
    raw_key,
    read_raw,
)

from common.storage import MemoryObjectStore, object_key


def _store_with(sha: str, body: bytes) -> MemoryObjectStore:
    store = MemoryObjectStore()
    store.seed(object_key(sha), body)
    return store


def test_raw_key_matches_the_ingest_key() -> None:
    sha = "ab" + "0" * 62
    assert raw_key(sha) == object_key(sha) == f"raw/ab/00/{sha}"


def test_raw_key_honours_prefix() -> None:
    sha = "cd" + "0" * 62
    assert raw_key(sha, "archive") == f"archive/cd/00/{sha}"


async def test_read_raw_returns_bytes() -> None:
    sha = "a" * 64
    store = _store_with(sha, b"hello")
    assert await read_raw(store, sha) == b"hello"


async def test_read_raw_under_ceiling() -> None:
    sha = "b" * 64
    store = _store_with(sha, b"hello")
    assert await read_raw(store, sha, max_bytes=1024) == b"hello"


async def test_read_raw_rejects_oversize_without_downloading() -> None:
    sha = "c" * 64
    store = _store_with(sha, b"x" * 1024)
    with pytest.raises(RawFileTooLargeError):
        await read_raw(store, sha, max_bytes=512)


async def test_read_raw_missing_object_raises() -> None:
    with pytest.raises(RawFileNotFoundError):
        await read_raw(MemoryObjectStore(), "d" * 64)


async def test_read_raw_surfaces_store_outage_distinctly() -> None:
    """An unreachable store is not the same as a missing object.

    The consumer skips a missing object permanently but leaves an
    unreadable one for the backfill scan to retry, so the two cannot
    collapse into one error.
    """
    from common.storage import ObjectStorageError

    sha = "e" * 64
    store = _store_with(sha, b"payload")
    store.available = False
    with pytest.raises(ObjectStorageError) as exc:
        await read_raw(store, sha)
    assert not isinstance(exc.value, RawFileNotFoundError)
