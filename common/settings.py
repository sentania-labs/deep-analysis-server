"""Shared pydantic-settings base for all services."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseServiceSettings(BaseSettings):
    service_name: str
    log_level: str = "INFO"
    database_url: str
    redis_url: str
    jwt_public_key_path: Path
    jwt_issuer: str = "deep-analysis-auth"
    jwt_audience: str = "deep-analysis"

    model_config = SettingsConfigDict(env_prefix="DA_", env_nested_delimiter="__")
