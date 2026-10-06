from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from web_service import analytics_client
from web_service import deps as web_deps
from web_service import main as web_main


@pytest.mark.asyncio
async def test_admin_dashboard_escapes_and_bounds_raw_snippet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snippet = "<script>alert('diagnostic')</script>" + ("x" * 2500)
    started = datetime(2026, 10, 6, 12, tzinfo=UTC)

    async def fake_scrapers(_url: str, _token: str) -> list[dict[str, Any]]:
        return [
            {
                "scraper_name": "mtgo",
                "enabled": True,
                "interval_hours": 24,
                "consecutive_failures": 1,
                "is_broken": False,
                "last_error": "changed markup",
                "last_raw_snippet": snippet[:2000],
                "is_running": False,
            }
        ]

    async def fake_history(_url: str, _token: str, _name: str) -> list[dict[str, Any]]:
        return [
            {
                "started_at": started,
                "finished_at": started,
                "duration_seconds": 1.25,
                "status": "failed",
                "events_found": 3,
                "events_new": 1,
                "events_empty": 2,
                "results_stored": 8,
            }
        ]

    admin = web_deps.BrowserUser(
        user_id=1,
        email="admin@local",
        role="admin",
        must_change_password=False,
        scope=None,
        token="admin-token",
    )

    async def current_admin() -> web_deps.BrowserUser:
        return admin

    monkeypatch.setattr(analytics_client, "admin_get_scrapers", fake_scrapers)
    monkeypatch.setattr(analytics_client, "admin_get_scraper_run_history", fake_history)
    web_main.app.dependency_overrides[web_deps.get_current_browser_user] = current_admin
    try:
        transport = httpx.ASGITransport(app=web_main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://web") as client:
            response = await client.get("/admin/scrapers")
    finally:
        web_main.app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;alert" in response.text
    assert "Recent runs" in response.text
    assert "1.2s" in response.text
    assert "x" * 2001 not in response.text
