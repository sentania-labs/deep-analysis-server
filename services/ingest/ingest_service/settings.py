"""Ingest-service-specific settings."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import SettingsConfigDict

from common.settings import BaseServiceSettings


class IngestSettings(BaseServiceSettings):
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # Root of the raw-file archive. The ingest container mounts a
    # dedicated volume at this path; content-addressed sharded layout
    # under it (see storage.py).
    ingest_raw_path: Path = Path("/data/raw/")
    # Hard ceiling on individual upload size. Enforced before buffering.
    ingest_max_file_bytes: int = 100 * 1024 * 1024


_settings: IngestSettings | None = None


def get_settings() -> IngestSettings:
    global _settings
    if _settings is None:
        _settings = IngestSettings(service_name="ingest")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
