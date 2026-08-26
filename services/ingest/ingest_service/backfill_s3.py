"""Backfill the legacy filesystem archive into the object store.

Reads every row in ``ingest.game_log_files``, finds the matching file
on the legacy ``raw_archive`` volume, and uploads it to the
S3-compatible archive under its content-addressed key. Then it
verifies, by asking the store which keys are actually present.

Properties this tool is built around:

* **Idempotent.** Keys are content-addressed, so a re-run re-uploads
  nothing. Running it twice is the supported way to confirm the first
  run finished.
* **Verifiable.** It reports expected / uploaded / already present /
  missing source / hash mismatch / failed / verified, and exits
  non-zero if the verify pass does not account for every row. A silent
  partial migration is the outcome worth engineering against.
* **Non-destructive.** It never deletes, truncates or renames anything
  on the source volume. Reclaiming that space is a separate, deliberate
  operator step (see ``docs/deploy.md``).

Usage (from the repo, against a live database and store)::

    uv run python -m ingest_service.backfill_s3 --source /data/raw

Or as a one-shot against the compose stack::

    docker compose --profile backfill run --rm raw-backfill

Add ``--dry-run`` to report what would be uploaded without writing.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import text

from common.logging import configure_logging
from common.storage import ObjectStorageError, ObjectStore, S3ObjectStore, object_key
from ingest_service.db import get_sessionmaker
from ingest_service.settings import get_settings
from ingest_service.storage import legacy_extension_for, mime_for

_log = logging.getLogger("ingest.backfill_s3")

# Extensions the legacy archive may have used for a given sha. The
# recorded storage_path is tried first; these cover rows written before
# the content-type map settled.
_FALLBACK_EXTS = (".dat", ".log", ".txt", ".xml", ".bin", "")

# How many objects to move at once. The store is local to the stack and
# the objects are small (35 KB average), so this is about keeping the
# run short, not about saturating anything.
_CONCURRENCY = 8


@dataclass
class BackfillCounts:
    """Everything an operator needs to decide whether this worked."""

    expected: int = 0
    uploaded: int = 0
    already_present: int = 0
    missing_source: int = 0
    hash_mismatch: int = 0
    failed: int = 0
    bytes_uploaded: int = 0
    storage_paths_updated: int = 0
    source_files_scanned: int = 0
    orphan_source_files: int = 0
    verified: int = 0

    @property
    def ok(self) -> bool:
        """True when every expected row is present in the store."""
        return (
            self.failed == 0
            and self.hash_mismatch == 0
            and self.missing_source == 0
            and self.verified == self.expected
        )


@dataclass
class _Row:
    sha256: str
    content_type: str
    size_bytes: int
    storage_path: str


@dataclass
class _Outcome:
    row: _Row
    state: str
    size: int = 0
    detail: str = ""


@dataclass
class _SourceIndex:
    """Every file on the legacy volume, indexed by sha-from-filename."""

    by_sha: dict[str, Path] = field(default_factory=dict)
    scanned: int = 0


def index_source(root: Path) -> _SourceIndex:
    """Walk the legacy archive and index files by the sha in their name."""
    index = _SourceIndex()
    if not root.exists():
        return index
    for path in root.rglob("*"):
        if not path.is_file() or path.name.endswith(".tmp"):
            continue
        index.scanned += 1
        stem = path.name.split(".", 1)[0].lower()
        if len(stem) == 64:
            index.by_sha.setdefault(stem, path)
    return index


def locate_source(row: _Row, root: Path, index: _SourceIndex) -> Path | None:
    """Find the legacy file for ``row``, by recorded path then by index."""
    candidates: list[Path] = []
    recorded = row.storage_path.strip()
    # A pre-migration storage_path is a relative sharded path; a
    # post-migration one is an object key, which is not on disk.
    if recorded and not recorded.startswith(("s3://", "raw/")):
        candidates.append(root / recorded)
    sha = row.sha256
    shard = root / sha[0:2] / sha[2:4]
    ext = legacy_extension_for(row.content_type)
    candidates.append(shard / f"{sha}{ext}")
    candidates.extend(shard / f"{sha}{e}" for e in _FALLBACK_EXTS)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return index.by_sha.get(sha)


async def _load_rows(sm: Any) -> list[_Row]:
    async with sm() as session:
        result = await session.execute(
            text(
                "SELECT sha256, content_type, size_bytes, storage_path "
                "FROM ingest.game_log_files ORDER BY first_uploaded_at"
            )
        )
        return [
            _Row(
                sha256=str(r[0]),
                content_type=str(r[1]),
                size_bytes=int(r[2] or 0),
                storage_path=str(r[3] or ""),
            )
            for r in result.all()
        ]


async def _migrate_one(
    row: _Row,
    root: Path,
    index: _SourceIndex,
    store: ObjectStore,
    key_prefix: str,
    dry_run: bool,
) -> _Outcome:
    key = object_key(row.sha256, key_prefix)
    try:
        if await store.exists(key):
            return _Outcome(row=row, state="already_present")
    except ObjectStorageError as exc:
        return _Outcome(row=row, state="failed", detail=str(exc))

    path = locate_source(row, root, index)
    if path is None:
        return _Outcome(row=row, state="missing_source")

    try:
        content = await asyncio.to_thread(path.read_bytes)
    except OSError as exc:
        return _Outcome(row=row, state="failed", detail=str(exc))

    # The filename is a claim; the bytes are the fact. A file whose
    # content does not hash to its key is not that object, and
    # uploading it under that key would corrupt the archive silently.
    actual = hashlib.sha256(content).hexdigest()
    if actual != row.sha256:
        return _Outcome(
            row=row,
            state="hash_mismatch",
            detail=f"{path} hashes to {actual}",
        )

    if dry_run:
        return _Outcome(row=row, state="would_upload", size=len(content))

    try:
        await store.put(key, content, content_type=mime_for(row.content_type))
    except ObjectStorageError as exc:
        return _Outcome(row=row, state="failed", detail=str(exc))
    return _Outcome(row=row, state="uploaded", size=len(content))


async def _update_storage_paths(sm: Any, rows: list[_Row], key_prefix: str) -> int:
    """Point ``storage_path`` at the object key. Idempotent."""
    updates = [
        {"sha": r.sha256, "sp": object_key(r.sha256, key_prefix)}
        for r in rows
        if r.storage_path != object_key(r.sha256, key_prefix)
    ]
    if not updates:
        return 0
    async with sm() as session:
        for chunk_start in range(0, len(updates), 500):
            chunk = updates[chunk_start : chunk_start + 500]
            await session.execute(
                text("UPDATE ingest.game_log_files SET storage_path = :sp WHERE sha256 = :sha"),
                chunk,
            )
        await session.commit()
    return len(updates)


async def _verify(rows: list[_Row], store: ObjectStore, key_prefix: str) -> int:
    """Count how many rows have an object actually present in the store."""
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def _one(row: _Row) -> bool:
        async with sem:
            try:
                return await store.exists(object_key(row.sha256, key_prefix))
            except ObjectStorageError:
                return False

    results = await asyncio.gather(*(_one(r) for r in rows))
    return sum(1 for r in results if r)


async def run_backfill(
    sm: Any,
    store: ObjectStore,
    source_root: Path,
    key_prefix: str = "raw",
    dry_run: bool = False,
    limit: int | None = None,
) -> BackfillCounts:
    """Migrate the legacy archive into ``store`` and verify the result."""
    counts = BackfillCounts()
    rows = await _load_rows(sm)
    if limit is not None:
        rows = rows[:limit]
    counts.expected = len(rows)

    index = await asyncio.to_thread(index_source, source_root)
    counts.source_files_scanned = index.scanned
    known = {r.sha256 for r in rows}
    counts.orphan_source_files = sum(1 for sha in index.by_sha if sha not in known)

    sem = asyncio.Semaphore(_CONCURRENCY)

    async def _one(row: _Row) -> _Outcome:
        async with sem:
            return await _migrate_one(row, source_root, index, store, key_prefix, dry_run)

    outcomes = await asyncio.gather(*(_one(r) for r in rows))

    for outcome in outcomes:
        if outcome.state in {"uploaded", "would_upload"}:
            counts.uploaded += 1
            counts.bytes_uploaded += outcome.size
        elif outcome.state == "already_present":
            counts.already_present += 1
        elif outcome.state == "missing_source":
            counts.missing_source += 1
            _log.warning("no source file for sha=%s", outcome.row.sha256)
        elif outcome.state == "hash_mismatch":
            counts.hash_mismatch += 1
            _log.error("hash mismatch sha=%s %s", outcome.row.sha256, outcome.detail)
        else:
            counts.failed += 1
            _log.error("upload failed sha=%s: %s", outcome.row.sha256, outcome.detail)

    if not dry_run:
        counts.storage_paths_updated = await _update_storage_paths(sm, rows, key_prefix)
        counts.verified = await _verify(rows, store, key_prefix)

    return counts


def _format(counts: BackfillCounts, dry_run: bool) -> str:
    lines = ["=== raw archive backfill " + ("(DRY RUN) ===" if dry_run else "===")]
    for key, value in asdict(counts).items():
        lines.append(f"  {key:<22} {value}")
    lines.append(f"  {'result':<22} {'OK' if counts.ok or dry_run else 'INCOMPLETE'}")
    return "\n".join(lines)


async def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Backfill the raw archive into object storage.")
    parser.add_argument(
        "--source",
        default="/data/raw",
        help="Root of the legacy raw_archive volume (default: /data/raw)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report only; upload nothing.")
    parser.add_argument("--limit", type=int, default=None, help="Only process the first N rows.")
    args = parser.parse_args(argv)

    configure_logging("ingest-backfill")
    settings = get_settings()
    store = S3ObjectStore(settings.s3_config())
    if not args.dry_run:
        created = await store.ensure_bucket()
        if created:
            _log.info("created bucket %s", settings.s3_bucket)

    counts = await run_backfill(
        get_sessionmaker(),
        store,
        Path(args.source),
        key_prefix=settings.s3_key_prefix,
        dry_run=args.dry_run,
        limit=args.limit,
    )
    await store.aclose()
    print(_format(counts, args.dry_run))
    if args.dry_run:
        return 0
    return 0 if counts.ok else 1


def main() -> int:
    return asyncio.run(_main())


if __name__ == "__main__":
    sys.exit(main())
