"""Analytics-service-specific settings."""

from __future__ import annotations

from pydantic_settings import SettingsConfigDict

from common.settings import BaseServiceSettings


class AnalyticsSettings(BaseServiceSettings):
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    scryfall_sync_interval_days: int = 7
    mtgo_scrape_interval_hours: int = 24


_settings: AnalyticsSettings | None = None


def get_settings() -> AnalyticsSettings:
    global _settings
    if _settings is None:
        _settings = AnalyticsSettings(service_name="analytics")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
