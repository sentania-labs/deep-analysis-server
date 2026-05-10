"""Tests for raw-file resolution under the sharded archive layout."""

from __future__ import annotations

from pathlib import Path

import pytest
from parser_service.storage import RawFileNotFoundError, read_raw, resolve_path


def _write_shard(root: Path, sha: str, ext: str, content: bytes) -> Path:
    shard = root / sha[0:2] / sha[2:4]
    shard.mkdir(parents=True, exist_ok=True)
    target = shard / f"{sha}{ext}"
    target.write_bytes(content)
    return target


def test_resolve_finds_dat_first(tmp_path: Path) -> None:
    sha = "a" * 64
    expected = _write_shard(tmp_path, sha, ".dat", b"payload")
    assert resolve_path(sha, tmp_path) == expected


def test_resolve_falls_back_to_log(tmp_path: Path) -> None:
    sha = "b" * 64
    expected = _write_shard(tmp_path, sha, ".log", b"payload")
    assert resolve_path(sha, tmp_path) == expected


def test_resolve_honours_hint_ext(tmp_path: Path) -> None:
    sha = "c" * 64
    expected = _write_shard(tmp_path, sha, ".log", b"payload")
    assert resolve_path(sha, tmp_path, hint_ext=".log") == expected


def test_resolve_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(RawFileNotFoundError):
        resolve_path("d" * 64, tmp_path)


def test_read_raw_returns_bytes(tmp_path: Path) -> None:
    sha = "e" * 64
    _write_shard(tmp_path, sha, ".dat", b"hello")
    assert read_raw(sha, tmp_path) == b"hello"
