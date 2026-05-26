"""Admin MOTD endpoints — set, read, clear, expiration behavior.

Covers the admin-configurable site banner (MOTD) stored in
auth.server_settings with keys ``motd:message``, ``motd:severity``,
and ``motd:expires_at``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auth_service.models import User
from auth_service.passwords import hash_password


async def _login(client: Any, email: str, password: str) -> str:
    resp = await client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return str(resp.json()["access_token"])


async def _create_admin(db: Any) -> tuple[str, str]:
    """Insert an admin user and return (email, plaintext_password)."""
    email = "admin@local"
    pw = "supersecurepassword123"
    user = User(email=email, password_hash=hash_password(pw), role="admin")
    db.add(user)
    await db.commit()
    return email, pw


@pytest.mark.asyncio
async def test_get_motd_no_banner(client: Any, db_session: Any) -> None:
    """GET /admin/settings/motd returns active=False when no banner is set."""
    email, pw = await _create_admin(db_session)
    token = await _login(client, email, pw)
    resp = await client.get("/admin/settings/motd", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] is False


@pytest.mark.asyncio
async def test_set_and_get_motd(client: Any, db_session: Any) -> None:
    """PUT then GET returns the active banner."""
    email, pw = await _create_admin(db_session)
    token = await _login(client, email, pw)
    expires = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
    resp = await client.put(
        "/admin/settings/motd",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Maintenance tonight", "severity": "warning", "expires_at": expires},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] is True
    assert data["message"] == "Maintenance tonight"
    assert data["severity"] == "warning"

    # GET confirms it
    resp2 = await client.get("/admin/settings/motd", headers={"Authorization": f"Bearer {token}"})
    assert resp2.status_code == 200
    assert resp2.json()["active"] is True
    assert resp2.json()["message"] == "Maintenance tonight"


@pytest.mark.asyncio
async def test_clear_motd(client: Any, db_session: Any) -> None:
    """DELETE clears the active banner."""
    email, pw = await _create_admin(db_session)
    token = await _login(client, email, pw)
    expires = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
    await client.put(
        "/admin/settings/motd",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Test", "severity": "info", "expires_at": expires},
    )
    resp = await client.delete("/admin/settings/motd", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 204

    resp2 = await client.get("/admin/settings/motd", headers={"Authorization": f"Bearer {token}"})
    assert resp2.json()["active"] is False


@pytest.mark.asyncio
async def test_motd_expired_returns_inactive(client: Any, db_session: Any) -> None:
    """An expired MOTD shows as inactive."""
    email, pw = await _create_admin(db_session)
    token = await _login(client, email, pw)
    # Set expires_at to the past
    expires = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    await client.put(
        "/admin/settings/motd",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Old news", "severity": "info", "expires_at": expires},
    )
    resp = await client.get("/admin/settings/motd", headers={"Authorization": f"Bearer {token}"})
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_public_motd_endpoint(client: Any, db_session: Any) -> None:
    """GET /auth/motd returns the active MOTD without auth."""
    email, pw = await _create_admin(db_session)
    token = await _login(client, email, pw)
    expires = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
    await client.put(
        "/admin/settings/motd",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Public notice", "severity": "info", "expires_at": expires},
    )
    # No auth header
    resp = await client.get("/auth/motd")
    assert resp.status_code == 200
    assert resp.json()["active"] is True
    assert resp.json()["message"] == "Public notice"


@pytest.mark.asyncio
async def test_set_motd_replaces_previous(client: Any, db_session: Any) -> None:
    """Setting a new MOTD replaces the old one."""
    email, pw = await _create_admin(db_session)
    token = await _login(client, email, pw)
    expires = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
    await client.put(
        "/admin/settings/motd",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "First", "severity": "info", "expires_at": expires},
    )
    await client.put(
        "/admin/settings/motd",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "Second", "severity": "warning", "expires_at": expires},
    )
    resp = await client.get("/admin/settings/motd", headers={"Authorization": f"Bearer {token}"})
    assert resp.json()["message"] == "Second"
    assert resp.json()["severity"] == "warning"
