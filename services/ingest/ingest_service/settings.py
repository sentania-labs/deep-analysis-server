"""Ingest-service-specific settings."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import SettingsConfigDict

from common.settings import S3StorageSettings


class IngestSettings(S3StorageSettings):
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # The raw archive lives in the S3-compatible object store. Bucket,
    # endpoint and credentials come from S3StorageSettings; there is no
    # filesystem archive and no backend selector.
    #
    # Hard ceiling on individual upload size. Enforced before buffering.
    ingest_max_file_bytes: int = 100 * 1024 * 1024

    # --- Legacy raw-archive migration (issue #161) ---------------------
    #
    # Hosts upgraded from the pre-#135 filesystem archive still have
    # thousands of files that exist only on the old volume. Until they
    # are in the object store, anything that re-reads a raw log fails.
    # Default ON so a deploy closes that gap with no operator step; an
    # operator can turn it off and drive the one-shot job by hand
    # instead. The toggle and the live progress are on the admin
    # Settings page.
    s3_auto_backfill: bool = True

    # Where the legacy archive is mounted inside the container. Empty or
    # absent means there is nothing to migrate, which is the normal case
    # for a fresh install.
    legacy_archive_path: Path = Path("/data/raw")

    # How long the startup task waits before re-checking a lock another
    # replica holds.
    s3_auto_backfill_retry_seconds: float = 60.0


_settings: IngestSettings | None = None


def get_settings() -> IngestSettings:
    global _settings
    if _settings is None:
        _settings = IngestSettings(service_name="ingest")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
