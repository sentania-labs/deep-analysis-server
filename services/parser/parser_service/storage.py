"""Read raw uploaded files from the shared archive volume.

The ingest service writes content-addressed shards under
``<root>/<sha[0:2]>/<sha[2:4]>/<sha>.<ext>`` and records the
relative path in ``ingest.game_log_files.storage_path``. The parser
mounts the same volume read-only and reads at that path.
"""

from __future__ import annotations

from pathlib import Path

# Match-log uploads land as ``.dat`` per ingest's content-type → ext map,
# even when the actual payload is a plaintext MTGO log. We try the
# recorded path first, then fall back to common alternatives.
_FALLBACK_EXTS = (".dat", ".log", ".txt", ".bin")


class RawFileNotFoundError(FileNotFoundError):
    """Raised when no raw file can be located for a given sha256."""


def resolve_path(sha256: str, root: Path, hint_ext: str | None = None) -> Path:
    """Return the on-disk path for ``sha256``, trying common extensions.

    Caller may pass ``hint_ext`` (e.g., the ``storage_path`` suffix
    recorded by ingest) to short-circuit the fallback search.
    """
    shard = root / sha256[0:2] / sha256[2:4]
    candidates: list[str] = []
    if hint_ext:
        candidates.append(hint_ext if hint_ext.startswith(".") else f".{hint_ext}")
    candidates.extend(e for e in _FALLBACK_EXTS if e not in candidates)
    for ext in candidates:
        candidate = shard / f"{sha256}{ext}"
        if candidate.exists():
            return candidate
    raise RawFileNotFoundError(
        f"no raw file found for sha {sha256} under {shard}"
    )


def read_raw(sha256: str, root: Path, hint_ext: str | None = None) -> bytes:
    return resolve_path(sha256, root, hint_ext).read_bytes()
