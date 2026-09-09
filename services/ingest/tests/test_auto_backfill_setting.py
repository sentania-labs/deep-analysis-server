"""Automatic migration starts require a successfully resolved setting."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from ingest_service import main
from ingest_service.settings import IngestSettings


@pytest.mark.parametrize(
    ("value", "fallback", "expected"),
    [
        (None, True, True),
        (None, False, False),
        (False, True, False),
        (True, False, True),
        ("false", True, False),
    ],
)
async def test_resolve_auto_backfill_setting(value, fallback, expected):
    session = AsyncMock()
    session.execute.return_value = MagicMock(scalar_one_or_none=lambda: value)
    sm = MagicMock()
    sm.return_value.__aenter__.return_value = session

    assert await main._read_auto_backfill_setting(sm, fallback=fallback) is expected


@pytest.mark.parametrize("failure_point", ["connect", "query"])
async def test_settings_read_failure_prevents_automatic_start(monkeypatch, failure_point):
    session = AsyncMock()
    session.execute.return_value = MagicMock(scalar_one_or_none=lambda: False)
    sm = MagicMock()
    sm.return_value.__aenter__.return_value = session
    if failure_point == "connect":
        sm.return_value.__aenter__.side_effect = ConnectionError("database unavailable")
    else:
        session.execute.side_effect = ConnectionError("database unavailable")

    start = MagicMock()
    monkeypatch.setattr(main, "get_sessionmaker", lambda: sm)
    settings = IngestSettings(service_name="ingest", s3_auto_backfill=True)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "start_metrics_server", MagicMock())
    monkeypatch.setattr(main, "get_store", MagicMock())
    monkeypatch.setattr(main.auto_backfill, "start", start)

    async with main.lifespan(main.app):
        assert main._auto_backfill_enabled is False
        assert main._backfill_task is None
        sm.return_value.__aenter__.side_effect = None
        session.execute.side_effect = None
        assert await main._read_auto_backfill_setting(sm, fallback=True) is False
        start.assert_not_called()

    start.assert_not_called()
