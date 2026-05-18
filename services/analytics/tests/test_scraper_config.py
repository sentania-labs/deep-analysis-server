"""Unit tests for scraper config schemas and scheduler config-awareness.

Tests the Pydantic schemas and the pure logic around config reading.
No DB or HTTP needed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from analytics_service.schemas import (
    ScraperConfigListResponse,
    ScraperConfigResponse,
    ScraperConfigUpdate,
)
from pydantic import ValidationError

# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


def test_scraper_config_response_defaults() -> None:
    resp = ScraperConfigResponse(scraper_name="mtgo")
    assert resp.scraper_name == "mtgo"
    assert resp.enabled is True
    assert resp.interval_hours == 24
    assert resp.consecutive_failures == 0
    assert resp.is_broken is False
    assert resp.last_error is None


def test_scraper_config_response_full() -> None:
    resp = ScraperConfigResponse(
        scraper_name="mtgtop8",
        enabled=False,
        interval_hours=12,
        consecutive_failures=3,
        is_broken=True,
        last_error="connection timeout",
    )
    assert resp.enabled is False
    assert resp.interval_hours == 12
    assert resp.is_broken is True


def test_scraper_config_list_response() -> None:
    resp = ScraperConfigListResponse(
        scrapers=[
            ScraperConfigResponse(scraper_name="mtgo"),
            ScraperConfigResponse(scraper_name="mtgtop8"),
        ]
    )
    assert len(resp.scrapers) == 2
    names = {s.scraper_name for s in resp.scrapers}
    assert names == {"mtgo", "mtgtop8"}


def test_scraper_config_update_empty() -> None:
    """Both fields can be None — the endpoint rejects this, not the schema."""
    update = ScraperConfigUpdate()
    assert update.enabled is None
    assert update.interval_hours is None


def test_scraper_config_update_enabled_only() -> None:
    update = ScraperConfigUpdate(enabled=False)
    assert update.enabled is False
    assert update.interval_hours is None


def test_scraper_config_update_interval_only() -> None:
    update = ScraperConfigUpdate(interval_hours=12)
    assert update.enabled is None
    assert update.interval_hours == 12


def test_scraper_config_update_both() -> None:
    update = ScraperConfigUpdate(enabled=True, interval_hours=48)
    assert update.enabled is True
    assert update.interval_hours == 48


def test_scraper_config_update_interval_min() -> None:
    update = ScraperConfigUpdate(interval_hours=1)
    assert update.interval_hours == 1


def test_scraper_config_update_interval_max() -> None:
    update = ScraperConfigUpdate(interval_hours=168)
    assert update.interval_hours == 168


def test_scraper_config_update_interval_too_low() -> None:
    try:
        ScraperConfigUpdate(interval_hours=0)
        assert False, "should have raised"  # noqa: B011
    except ValidationError:
        pass


def test_scraper_config_update_interval_too_high() -> None:
    try:
        ScraperConfigUpdate(interval_hours=169)
        assert False, "should have raised"  # noqa: B011
    except ValidationError:
        pass


# --------------------------------------------------------------------------- #
# _mtgo_scrape_due logic
# --------------------------------------------------------------------------- #

# Duplicated from main.py to avoid triggering the full import chain
# (which hits common.metrics — not available in the local test venv).


def _mtgo_scrape_due(health: dict[str, Any], interval_hours: int) -> bool:
    last = health.get("last_run_at")
    if last is None:
        return True
    now = datetime.now(UTC)
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (now - last) >= timedelta(hours=interval_hours)


def test_scrape_due_no_last_run() -> None:
    """When health has no last_run_at, scrape is always due."""
    health: dict[str, object] = {"last_run_at": None}
    assert _mtgo_scrape_due(health, 24) is True


def test_scrape_due_recent_run() -> None:
    """When last_run_at is within the interval, scrape is not due."""
    health: dict[str, object] = {"last_run_at": datetime.now(UTC) - timedelta(hours=1)}
    assert _mtgo_scrape_due(health, 24) is False


def test_scrape_due_old_run() -> None:
    """When last_run_at is older than the interval, scrape is due."""
    health: dict[str, object] = {"last_run_at": datetime.now(UTC) - timedelta(hours=25)}
    assert _mtgo_scrape_due(health, 24) is True
