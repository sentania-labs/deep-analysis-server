"""Thin HTTP client over the internal auth service.

The web service calls auth directly over the backend compose network
(``http://auth:8000``) rather than looping through the Caddy gateway.
This module centralizes those calls so handlers don't re-implement
URL formatting or error translation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx


@dataclass
class LoginResult:
    access_token: str
    refresh_token: str
    expires_in: int
    must_change_password: bool


@dataclass
class MeResult:
    user_id: int
    email: str
    role: str
    must_change_password: bool


@dataclass
class AgentItem:
    agent_id: str
    machine_name: str
    client_version: str | None
    created_at: datetime | None
    last_seen_at: datetime | None
    revoked_at: datetime | None


class AuthClientError(Exception):
    """Auth call failed for reasons other than bad credentials."""


class InvalidCredentials(Exception):
    """Auth rejected the login as invalid credentials."""


def _parse_dt(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


async def login(base_url: str, email: str, password: str) -> LoginResult:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/auth/login",
                json={"email": email, "password": password},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /login transport error: {exc}") from exc
    if resp.status_code == 401:
        raise InvalidCredentials()
    if resp.status_code >= 400:
        raise AuthClientError(f"auth /login returned {resp.status_code}: {resp.text}")
    data = resp.json()
    return LoginResult(
        access_token=data["access_token"],
        refresh_token=data["refresh_token"],
        expires_in=int(data["expires_in"]),
        must_change_password=bool(data["must_change_password"]),
    )


async def change_password(
    base_url: str,
    token: str,
    current_password: str,
    new_password: str,
) -> tuple[bool, str | None]:
    """Try to change the password. Returns (ok, error_code).

    On 204, returns (True, None). On a validation/auth failure, returns
    (False, <error-code-from-auth>) so the caller can render an inline
    message.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/auth/password/change",
                headers={"Authorization": f"Bearer {token}"},
                json={"current_password": current_password, "new_password": new_password},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /password/change transport error: {exc}") from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code in (400, 401):
        try:
            detail = resp.json().get("detail") or {}
            code = detail.get("error") if isinstance(detail, dict) else None
        except ValueError:
            code = None
        return False, code or "password_change_failed"
    raise AuthClientError(f"auth /password/change returned {resp.status_code}: {resp.text}")


async def logout(base_url: str, token: str) -> None:
    """Best-effort server-side session revoke.

    Errors are swallowed — the cookie clear is the real logout from
    the browser's perspective, and auth /logout is idempotent.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{base_url}/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError:
        return


async def get_me(base_url: str, token: str) -> MeResult:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /me transport error: {exc}") from exc
    if resp.status_code >= 400:
        raise AuthClientError(f"auth /me returned {resp.status_code}: {resp.text}")
    data = resp.json()
    return MeResult(
        user_id=int(data["user_id"]),
        email=str(data["email"]),
        role=str(data["role"]),
        must_change_password=bool(data["must_change_password"]),
    )


async def list_my_agents(
    base_url: str,
    token: str,
    limit: int = 50,
    offset: int = 0,
) -> list[AgentItem]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/auth/me/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "offset": offset},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /me/agents transport error: {exc}") from exc
    if resp.status_code >= 400:
        raise AuthClientError(f"auth /me/agents returned {resp.status_code}: {resp.text}")
    data = resp.json()
    return [
        AgentItem(
            agent_id=str(a["agent_id"]),
            machine_name=str(a["machine_name"]),
            client_version=a.get("client_version"),
            created_at=_parse_dt(a.get("created_at")),
            last_seen_at=_parse_dt(a.get("last_seen_at")),
            revoked_at=_parse_dt(a.get("revoked_at")),
        )
        for a in data.get("agents", [])
    ]


async def update_me(
    base_url: str,
    token: str,
    email: str,
) -> tuple[bool, str | None]:
    """Try to update the caller's email. Returns (ok, error_code).

    Maps known auth responses to UI-stable error codes:
      - 200 → (True, None)
      - 409 (email_already_exists) → (False, "email_taken")
      - other 4xx → (False, <auth-error-code-or-"invalid_email">)
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.patch(
                f"{base_url}/auth/me",
                headers={"Authorization": f"Bearer {token}"},
                json={"email": email},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /me PATCH transport error: {exc}") from exc
    if resp.status_code == 200:
        return True, None
    if resp.status_code == 409:
        return False, "email_taken"
    if resp.status_code in (400, 422):
        return False, "invalid_email"
    if resp.status_code in (401, 403):
        return False, "unauthorized"
    raise AuthClientError(f"auth /me PATCH returned {resp.status_code}: {resp.text}")


async def revoke_my_agent(
    base_url: str,
    token: str,
    agent_id: str,
) -> tuple[bool, str | None]:
    """Try to revoke one of the caller's own agents. Returns (ok, error_code).

    - 204 → (True, None)
    - 403 → (False, "forbidden")
    - 404 → (False, "not_found")
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/auth/me/agents/{agent_id}/revoke",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /me/agents revoke transport error: {exc}") from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code == 403:
        return False, "forbidden"
    if resp.status_code == 404:
        return False, "not_found"
    raise AuthClientError(f"auth /me/agents revoke returned {resp.status_code}: {resp.text}")
