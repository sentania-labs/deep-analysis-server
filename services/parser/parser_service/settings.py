"""Parser-service-specific settings."""

from __future__ import annotations

from pydantic_settings import SettingsConfigDict

from common.settings import S3StorageSettings

# Stamped on every match row at parse time so we can detect matches
# parsed by an older version and queue them for reparse.
PARSER_VERSION = "0.9.6"

# Backfill scanner picks up matches where ``parsed_with_version`` is
# NULL or less than this threshold, ensuring they get re-parsed with
# the current parser logic.  Bumped to 0.9.6 so all pre-event-stream
# matches are reprocessed and get their game_events rows populated.
REPARSE_MIN_VERSION = "0.9.6"


class ParserSettings(S3StorageSettings):
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # The raw archive is the S3-compatible object store ingest writes
    # to; bucket, endpoint and credentials come from S3StorageSettings.
    # Parser reads each object at the content-addressed key published
    # in ``ingest.game_log_files.storage_path``.
    #
    # Hard ceiling on log size we'll buffer in memory while parsing.
    parser_max_log_bytes: int = 50 * 1024 * 1024
    # Base URL for the analytics service (archetype classifier).
    # Empty string disables classification.
    analytics_service_url: str = "http://analytics:8000"
    # Interval (seconds) between backfill scans for ingested-but-not-parsed files.
    backfill_interval_seconds: int = 300
    # Maximum number of unparsed files to process per backfill scan.
    backfill_batch_size: int = 100


_settings: ParserSettings | None = None


def get_settings() -> ParserSettings:
    global _settings
    if _settings is None:
        _settings = ParserSettings(service_name="parser")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
