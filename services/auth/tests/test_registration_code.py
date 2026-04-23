"""POST /auth/agent/registration-code tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest


async def _login(client: Any, email: str, password: str) -> str:
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.mark.asyncio
async def test_mint_registration_code_requires_auth(client: Any) -> None:
    r = await client.post("/auth/agent/registration-code")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_mint_registration_code_success(client: Any, seed_user: dict[str, Any]) -> None:
    token = await _login(client, seed_user["email"], seed_user["password"])
    r = await client.post(
        "/auth/agent/registration-code",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert isinstance(body["code"], str) and body["code"]
    expires_at = datetime.fromisoformat(body["expires_at"])
    assert expires_at > datetime.now(UTC)
