"""Backfill of the legacy filesystem archive into object storage.

The dangerous outcome is a silent partial migration, so these tests
are about the counts being true: what was expected, what moved, what
was already there, and what could not be accounted for.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from ingest_service.backfill_s3 import index_source, locate_source, run_backfill
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.storage import S3Config, S3ObjectStore, object_key


def _sessionmaker_from(session: AsyncSession) -> Any:
    """Hand the backfill the test's own session (and never close it)."""

    class _Ctx:
        async def __aenter__(self) -> AsyncSession:
            return session

        async def __aexit__(self, *exc: object) -> bool:
            return False

    def _factory() -> _Ctx:
        return _Ctx()

    return _factory


def _write_legacy(root: Path, sha: str, body: bytes, ext: str = ".dat") -> Path:
    shard = root / sha[0:2] / sha[2:4]
    shard.mkdir(parents=True, exist_ok=True)
    path = shard / f"{sha}{ext}"
    path.write_bytes(body)
    return path


async def _seed_row(session: AsyncSession, sha: str, body: bytes, ct: str = "match-log") -> None:
    await session.execute(
        text(
            "INSERT INTO ingest.game_log_files "
            "(sha256, size_bytes, content_type, storage_path) "
            "VALUES (:sha, :size, :ct, :sp)"
        ),
        {
            "sha": sha,
            "size": len(body),
            "ct": ct,
            "sp": f"{sha[0:2]}/{sha[2:4]}/{sha}.dat",
        },
    )
    await session.commit()


@pytest.fixture
def backfill_store(object_store_server: str) -> S3ObjectStore:
    return S3ObjectStore(
        S3Config(
            endpoint_url=object_store_server,
            access_key="test",
            secret_key="testsecret",
            bucket="test-raw",
            force_path_style=True,
        )
    )


async def test_backfill_moves_objects_and_is_idempotent(
    db_session: AsyncSession,
    backfill_store: S3ObjectStore,
    tmp_path: Path,
) -> None:
    bodies = [f"legacy match log {i}".encode() for i in range(3)]
    shas = [hashlib.sha256(b).hexdigest() for b in bodies]
    for sha, body in zip(shas, bodies, strict=True):
        _write_legacy(tmp_path, sha, body)
        await _seed_row(db_session, sha, body)

    sm = _sessionmaker_from(db_session)

    first = await run_backfill(sm, backfill_store, tmp_path)
    assert first.expected == 3
    assert first.uploaded == 3
    assert first.already_present == 0
    assert first.missing_source == 0
    assert first.failed == 0
    assert first.hash_mismatch == 0
    assert first.verified == 3
    assert first.bytes_uploaded == sum(len(b) for b in bodies)
    assert first.ok is True

    # Bytes actually landed under the content-addressed key.
    for sha, body in zip(shas, bodies, strict=True):
        assert await backfill_store.get(object_key(sha)) == body

    # storage_path now points at the object key.
    rows = (
        await db_session.execute(text("SELECT sha256, storage_path FROM ingest.game_log_files"))
    ).all()
    assert {r[1] for r in rows} == {object_key(r[0]) for r in rows}

    second = await run_backfill(sm, backfill_store, tmp_path)
    assert second.expected == 3
    assert second.uploaded == 0, "re-run must upload nothing"
    assert second.already_present == 3
    assert second.bytes_uploaded == 0
    assert second.storage_paths_updated == 0
    assert second.verified == 3
    assert second.ok is True


async def test_backfill_leaves_the_source_volume_intact(
    db_session: AsyncSession,
    backfill_store: S3ObjectStore,
    tmp_path: Path,
) -> None:
    body = b"do not delete me"
    sha = hashlib.sha256(body).hexdigest()
    path = _write_legacy(tmp_path, sha, body)
    await _seed_row(db_session, sha, body)

    await run_backfill(_sessionmaker_from(db_session), backfill_store, tmp_path)

    assert path.exists()
    assert path.read_bytes() == body


async def test_backfill_reports_missing_source_rather_than_claiming_success(
    db_session: AsyncSession,
    backfill_store: S3ObjectStore,
    tmp_path: Path,
) -> None:
    body = b"row with no file on the volume"
    sha = hashlib.sha256(body).hexdigest()
    await _seed_row(db_session, sha, body)

    counts = await run_backfill(_sessionmaker_from(db_session), backfill_store, tmp_path)

    assert counts.expected == 1
    assert counts.uploaded == 0
    assert counts.missing_source == 1
    assert counts.verified == 0
    assert counts.ok is False


async def test_backfill_refuses_a_file_whose_bytes_do_not_match_its_name(
    db_session: AsyncSession,
    backfill_store: S3ObjectStore,
    tmp_path: Path,
) -> None:
    body = b"the real content"
    sha = hashlib.sha256(body).hexdigest()
    _write_legacy(tmp_path, sha, b"tampered content")
    await _seed_row(db_session, sha, body)

    counts = await run_backfill(_sessionmaker_from(db_session), backfill_store, tmp_path)

    assert counts.hash_mismatch == 1
    assert counts.uploaded == 0
    assert counts.ok is False
    assert await backfill_store.exists(object_key(sha)) is False


async def test_dry_run_uploads_nothing(
    db_session: AsyncSession,
    backfill_store: S3ObjectStore,
    tmp_path: Path,
) -> None:
    body = b"dry run body"
    sha = hashlib.sha256(body).hexdigest()
    _write_legacy(tmp_path, sha, body)
    await _seed_row(db_session, sha, body)

    counts = await run_backfill(
        _sessionmaker_from(db_session), backfill_store, tmp_path, dry_run=True
    )

    assert counts.uploaded == 1  # would upload
    assert counts.storage_paths_updated == 0
    assert await backfill_store.exists(object_key(sha)) is False


async def test_backfill_counts_orphan_files_on_the_volume(
    db_session: AsyncSession,
    backfill_store: S3ObjectStore,
    tmp_path: Path,
) -> None:
    body = b"tracked body"
    sha = hashlib.sha256(body).hexdigest()
    _write_legacy(tmp_path, sha, body)
    await _seed_row(db_session, sha, body)

    orphan = b"file on the volume with no database row"
    _write_legacy(tmp_path, hashlib.sha256(orphan).hexdigest(), orphan)

    counts = await run_backfill(_sessionmaker_from(db_session), backfill_store, tmp_path)

    assert counts.source_files_scanned == 2
    assert counts.orphan_source_files == 1
    assert counts.expected == 1
    assert counts.ok is True


def test_locate_source_falls_back_to_the_sha_index(tmp_path: Path) -> None:
    from ingest_service.backfill_s3 import _Row

    body = b"stored with an unexpected extension"
    sha = hashlib.sha256(body).hexdigest()
    path = _write_legacy(tmp_path, sha, body, ext=".log")
    row = _Row(sha256=sha, content_type="match-log", size_bytes=len(body), storage_path="")

    index = index_source(tmp_path)
    assert locate_source(row, tmp_path, index) == path
