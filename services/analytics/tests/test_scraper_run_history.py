from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from analytics_service import main as analytics_main
from analytics_service import mtgo_scraper
from analytics_service.deps import AuthenticatedUser, require_admin
from fastapi import HTTPException


class _Session:
    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


def _sessionmaker() -> Any:
    return _Session()


async def test_run_scrape_records_completed_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = mtgo_scraper.ScrapeResult(
        events_found=8,
        events_new=2,
        events_empty=1,
        results_stored=16,
    )
    recorded: list[tuple[str, mtgo_scraper.ScrapeResult, datetime, datetime]] = []

    async def fake_scrape(_sm: Any) -> mtgo_scraper.ScrapeResult:
        return expected

    async def fake_record(
        _session: Any,
        name: str,
        result: mtgo_scraper.ScrapeResult,
        started_at: datetime,
        finished_at: datetime,
    ) -> None:
        recorded.append((name, result, started_at, finished_at))

    monkeypatch.setattr(mtgo_scraper, "_run_scrape", fake_scrape)
    monkeypatch.setattr(mtgo_scraper, "record_run_history", fake_record)

    assert await mtgo_scraper.run_scrape(_sessionmaker) is expected
    assert recorded[0][0:2] == ("mtgo", expected)
    assert recorded[0][3] >= recorded[0][2]


async def test_history_endpoint_is_admin_only(monkeypatch: pytest.MonkeyPatch) -> None:
    async def forbidden() -> None:
        raise HTTPException(status_code=403, detail={"error": "forbidden"})

    analytics_main.app.dependency_overrides[require_admin] = forbidden
    transport = httpx.ASGITransport(app=analytics_main.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://analytics") as client:
            response = await client.get("/analytics/admin/scraper-health/mtgo/history")
    finally:
        analytics_main.app.dependency_overrides.pop(require_admin, None)
    assert response.status_code == 403


async def test_history_endpoint_returns_bounded_run_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = datetime(2026, 10, 6, 12, tzinfo=UTC)

    async def fake_history(_session: Any, name: str) -> list[dict[str, Any]]:
        assert name == "mtgo"
        return [
            {
                "id": 1,
                "scraper_name": name,
                "started_at": started,
                "finished_at": started + timedelta(seconds=2.5),
                "duration_seconds": 2.5,
                "status": "success",
                "events_found": 8,
                "events_new": 2,
                "events_empty": 1,
                "results_stored": 16,
            }
        ]

    analytics_main.app.dependency_overrides[require_admin] = lambda: AuthenticatedUser(
        user_id=1, role="admin"
    )
    monkeypatch.setattr(analytics_main, "get_sessionmaker", lambda: _sessionmaker)
    monkeypatch.setattr(analytics_main, "get_scraper_run_history", fake_history)
    transport = httpx.ASGITransport(app=analytics_main.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://analytics") as client:
            response = await client.get("/analytics/admin/scraper-health/mtgo/history")
    finally:
        analytics_main.app.dependency_overrides.pop(require_admin, None)
    assert response.status_code == 200
    assert response.json()["runs"][0]["results_stored"] == 16
