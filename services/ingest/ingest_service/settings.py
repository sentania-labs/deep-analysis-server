"""Ingest-service-specific settings."""

from __future__ import annotations

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


_settings: IngestSettings | None = None


def get_settings() -> IngestSettings:
    global _settings
    if _settings is None:
        _settings = IngestSettings(service_name="ingest")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
