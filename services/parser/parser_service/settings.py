"""Parser-service-specific settings."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import SettingsConfigDict

from common.settings import BaseServiceSettings


class ParserSettings(BaseServiceSettings):
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # Root of the raw-file archive — same volume the ingest service writes to,
    # mounted read-only here. Parser reads files at the sharded
    # ``<root>/<sha[0:2]>/<sha[2:4]>/<sha>.<ext>`` path published in
    # ``ingest.game_log_files.storage_path``.
    parser_raw_path: Path = Path("/data/raw/")
    # Hard ceiling on log size we'll buffer in memory while parsing.
    parser_max_log_bytes: int = 50 * 1024 * 1024
    # Interval (seconds) between backfill scans for ingested-but-not-parsed files.
    backfill_interval_seconds: int = 300


_settings: ParserSettings | None = None


def get_settings() -> ParserSettings:
    global _settings
    if _settings is None:
        _settings = ParserSettings(service_name="parser")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
