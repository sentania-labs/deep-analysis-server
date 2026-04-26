"""Web-service-specific settings."""

from __future__ import annotations

from pydantic_settings import SettingsConfigDict

from common.settings import BaseServiceSettings


class WebSettings(BaseServiceSettings):
    model_config = SettingsConfigDict(
        env_prefix="DA_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # Internal compose-network URL for the auth service. The web
    # service talks directly to auth over the backend network — it
    # does not go through the Caddy gateway.
    auth_service_url: str = "http://auth:8000"

    # Matches auth.access_token_ttl_seconds default. If auth is
    # reconfigured, set DA_SESSION_COOKIE_TTL_SECONDS to match.
    session_cookie_ttl_seconds: int = 900

    # Session cookie name. Kept here so the whole service uses one
    # constant rather than string-literal sprinkling.
    session_cookie_name: str = "da_session"


_settings: WebSettings | None = None


def get_settings() -> WebSettings:
    global _settings
    if _settings is None:
        _settings = WebSettings(service_name="web")  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
