"""Storage-layer assertions."""

from __future__ import annotations

import errno
import hashlib
from pathlib import Path

import pytest
from ingest_service import storage as storage_mod
from ingest_service.storage import (
    InsufficientStorageError,
    extension_for,
    storage_path_for,
    store_file,
)


def test_storage_path_sharding() -> None:
    sha = "abcd1234" + "0" * 56
    assert storage_path_for(sha, ".dat") == f"ab/cd/{sha}.dat"


def test_extension_for_known_and_unknown() -> None:
    assert extension_for("match-log") == ".dat"
    assert extension_for("decklist") == ".xml"
    assert extension_for("unknown") == ".bin"
    assert extension_for("unknown", "game.log") == ".log"


async def test_store_file_writes_and_is_idempotent(tmp_path: Path) -> None:
    data = b"hello world"
    sha = hashlib.sha256(data).hexdigest()
    path = await store_file(data, sha, ".dat", tmp_path)
    assert path.read_bytes() == data
    assert path.parent.parent.parent == tmp_path  # two shard levels

    # Re-store is a no-op and returns the same path.
    path2 = await store_file(b"different content", sha, ".dat", tmp_path)
    assert path2 == path
    assert path.read_bytes() == data


async def test_store_file_surfaces_enospc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"x" * 128
    sha = hashlib.sha256(data).hexdigest()

    def _boom(src, dst):  # noqa: ANN001 — mimicking os.rename signature
        raise OSError(errno.ENOSPC, "no space left")

    monkeypatch.setattr(storage_mod.os, "rename", _boom)
    with pytest.raises(InsufficientStorageError):
        await store_file(data, sha, ".dat", tmp_path)
