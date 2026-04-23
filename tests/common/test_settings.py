"""Tests for common.settings."""
from __future__ import annotations

from pathlib import Path

import pytest

from common.settings import BaseServiceSettings


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DA_SERVICE_NAME", "test")
    monkeypatch.setenv("DA_DATABASE_URL", "postgresql://x")
    monkeypatch.setenv("DA_REDIS_URL", "redis://x")
    monkeypatch.setenv("DA_JWT_PUBLIC_KEY_PATH", "/tmp/test.pem")

    s = BaseServiceSettings()
    assert s.service_name == "test"
    assert s.database_url == "postgresql://x"
    assert s.redis_url == "redis://x"
    assert s.jwt_public_key_path == Path("/tmp/test.pem")
    assert s.log_level == "INFO"


def test_settings_log_level_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DA_SERVICE_NAME", "test")
    monkeypatch.setenv("DA_DATABASE_URL", "postgresql://x")
    monkeypatch.setenv("DA_REDIS_URL", "redis://x")
    monkeypatch.setenv("DA_JWT_PUBLIC_KEY_PATH", "/tmp/test.pem")
    monkeypatch.setenv("DA_LOG_LEVEL", "DEBUG")

    s = BaseServiceSettings()
    assert s.log_level == "DEBUG"
