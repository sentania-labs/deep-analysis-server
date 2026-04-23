"""Auth-service-specific settings."""

from __future__ import annotations

from pathlib import Path

from common.settings import BaseServiceSettings


class AuthSettings(BaseServiceSettings):
    jwt_private_key_path: Path
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 2_592_000


_settings: AuthSettings | None = None


def get_settings() -> AuthSettings:
    global _settings
    if _settings is None:
        _settings = AuthSettings(service_name="auth")  # type: ignore[call-arg]
    return _settings
