"""Auth-service-specific settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import SettingsConfigDict

from common.settings import BaseServiceSettings


class AuthSettings(BaseServiceSettings):
    # Inherit env_prefix="DA_" from the base, but allow constructing
    # with field names (needed by tests) alongside env-var aliases.
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    jwt_private_key_path: Path
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 2_592_000
    password_change_token_ttl_seconds: int = 300
    bootstrap_admin_email: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "bootstrap_admin_email",
            "DA_BOOTSTRAP_ADMIN_EMAIL",
            "DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL",
        ),
    )
    bootstrap_admin_password: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "bootstrap_admin_password",
            "DA_BOOTSTRAP_ADMIN_PASSWORD",
            "DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD",
        ),
    )
    initial_admin_secret_path: Path = Path("/data/secrets/initial_admin.txt")


_settings: AuthSettings | None = None


def get_settings() -> AuthSettings:
    global _settings
    if _settings is None:
        _settings = AuthSettings(service_name="auth")  # type: ignore[call-arg]
    return _settings
