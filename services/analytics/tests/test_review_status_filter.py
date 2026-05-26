"""Tests for the holding-pen review_status filtering on user-facing stats.

The user-facing /stats endpoints must hide ``pending_review`` and
``'rejected'`` rows so the dashboard reflects the same world a regular
user would see in the match list. The admin endpoint surfaces them.

These tests cover the handler/aggregation wiring by patching
``_load_user_matches`` to return only what would survive the SQL
``WHERE m.review_status IS NULL`` clause — proving the contract: the
endpoint trusts the loader to filter, and the loader's SQL is the one
under test below as a separate string-level assertion.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _analytics_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("analytics-jwt-keys-review")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(pub_pem)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    yield pub_path


@pytest_asyncio.fixture
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    from analytics_service import main as _main

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _override_user(user_id: int = 7) -> Any:
    from analytics_service import deps as _deps

    fake = _deps.AuthenticatedUser(user_id=user_id, role="user")

    async def _dep() -> _deps.AuthenticatedUser:
        return fake

    return _dep


def test_load_user_matches_sql_filters_review_status() -> None:
    """String-level check: the user-facing match loader emits a
    ``review_status IS NULL`` clause. This is the contract that keeps
    holding-pen rows out of every endpoint that reaches through it."""
    import inspect

    from analytics_service import stats as _stats

    src = inspect.getsource(_stats._load_user_matches)
    assert "review_status IS NULL" in src

    src_list = inspect.getsource(_stats.list_matches)
    assert "review_status IS NULL" in src_list


def test_matches_detail_sql_filters_review_status() -> None:
    """Same string-level check on the single-match endpoint — fetching
    a pending_review match by ID must return 404 to a regular user."""
    import inspect

    from analytics_service import matches as _matches

    src = inspect.getsource(_matches.get_match)
    assert "review_status IS NULL" in src


def test_admin_matches_endpoint_supports_review_status_filter() -> None:
    """The admin match list endpoint must accept the ``review_status``
    query parameter so the UI can filter on it. This is a smoke check
    that the parameter is declared and the validation list is wired."""
    from analytics_service import main as _main

    valid = _main._VALID_REVIEW_STATUS_FILTERS
    assert {"all", "pending_review", "rejected", "normal"} <= valid


@pytest.mark.asyncio
async def test_summary_loader_filtering_contract(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: with a fake loader that already filtered out the
    holding-pen rows (mirrors what the SQL does), the summary reflects
    only the user-visible matches. Holding-pen rows would never reach
    the aggregator."""
    from analytics_service import deps as _deps
    from analytics_service import main as _main
    from analytics_service import stats as _stats

    # The user has 3 matches in the DB: 1 conclusive, 1 pending_review,
    # 1 rejected. The SQL filter (`WHERE review_status IS NULL`) means
    # the loader returns only the conclusive one.
    conclusive_id = uuid.uuid4()
    matches = [
        {
            "id": conclusive_id,
            "format": "Modern",
            "players": ["hero", "villain"],
            "played_at": datetime.now(UTC),
            "wins_by_player": {"hero": 2},
            "hero_player_name": "hero",
        }
    ]

    async def fake_loader(
        _db: Any,
        _user_id: int,
        *,
        date_from: Any = None,
        date_to: Any = None,
    ) -> list[dict[str, Any]]:
        return matches

    monkeypatch.setattr(_stats, "_load_user_matches", fake_loader)

    async def _no_redis() -> None:
        return None

    monkeypatch.setattr(_stats, "_get_redis_or_none", _no_redis)
    _main.app.dependency_overrides[_deps.require_user] = _override_user()
    try:
        r = await app_client.get("/analytics/stats/summary")
    finally:
        _main.app.dependency_overrides.clear()

    assert r.status_code == 200
    body = r.json()
    assert body["total_matches"] == 1
    assert body["wins"] == 1


@pytest.mark.asyncio
async def test_admin_review_endpoint_rejects_invalid_verdict(
    app_client: httpx.AsyncClient,
) -> None:
    """POST /analytics/admin/matches/{id}/review with a bogus
    review_status string must 422 rather than silently no-op."""
    from analytics_service import deps as _deps
    from analytics_service import main as _main

    fake = _deps.AuthenticatedUser(user_id=1, role="admin")

    async def _dep() -> _deps.AuthenticatedUser:
        return fake

    _main.app.dependency_overrides[_deps.require_admin] = _dep
    try:
        r = await app_client.post(
            f"/analytics/admin/matches/{uuid.uuid4()}/review",
            json={"review_status": "bogus_value"},
        )
    finally:
        _main.app.dependency_overrides.clear()
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_review_status"
