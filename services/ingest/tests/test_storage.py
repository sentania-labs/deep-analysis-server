"""Ingest storage helpers: keys, MIME mapping, adapter writes."""

from __future__ import annotations

import hashlib

import pytest
from ingest_service.storage import (
    legacy_extension_for,
    mime_for,
    storage_path_for,
    store_file,
)

from common.storage import (
    MemoryObjectStore,
    ObjectStoreFullError,
    ObjectStoreUnavailableError,
    object_key,
)


def test_storage_path_is_the_object_key() -> None:
    sha = "ab" + "0" * 62
    assert storage_path_for(sha) == f"raw/ab/00/{sha}"
    assert storage_path_for(sha) == object_key(sha)


def test_storage_path_honours_prefix() -> None:
    sha = "cd" + "1" * 62
    assert storage_path_for(sha, "archive") == f"archive/cd/11/{sha}"


def test_mime_for_known_and_unknown() -> None:
    assert mime_for("match-log") == "application/octet-stream"
    assert mime_for("decklist") == "application/xml"
    assert mime_for("reference-data") == "application/xml"
    assert mime_for("unknown") == "application/octet-stream"
    assert mime_for("something-else") == "application/octet-stream"


def test_legacy_extension_for_backfill_lookups() -> None:
    assert legacy_extension_for("match-log") == ".dat"
    assert legacy_extension_for("decklist") == ".xml"
    assert legacy_extension_for("unknown") == ".bin"
    assert legacy_extension_for("unknown", "game.log") == ".log"


async def test_store_file_writes_through_the_adapter() -> None:
    store = MemoryObjectStore()
    data = b"payload bytes"
    sha = hashlib.sha256(data).hexdigest()

    info = await store_file(store, data, sha, "match-log")

    assert info.key == object_key(sha)
    assert await store.get(object_key(sha)) == data
    assert (await store.head(object_key(sha))).content_type == "application/octet-stream"


async def test_store_file_is_idempotent() -> None:
    store = MemoryObjectStore()
    data = b"payload bytes"
    sha = hashlib.sha256(data).hexdigest()

    await store_file(store, data, sha, "match-log")
    await store_file(store, data, sha, "match-log")

    assert store.put_calls == 1


async def test_store_file_surfaces_storage_failure() -> None:
    store = MemoryObjectStore()
    store.available = False
    data = b"payload"
    sha = hashlib.sha256(data).hexdigest()

    with pytest.raises(ObjectStoreUnavailableError):
        await store_file(store, data, sha, "match-log")


def test_store_full_is_its_own_error() -> None:
    # The upload path maps this one to 507 and everything else to 503,
    # so the distinction has to survive.
    assert issubclass(ObjectStoreFullError, Exception)
    assert not issubclass(ObjectStoreFullError, ObjectStoreUnavailableError)
