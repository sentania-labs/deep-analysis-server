"""Thin HTTP client over the internal auth service.

The web service calls auth directly over the backend compose network
(``http://auth:8000``) rather than looping through the Caddy gateway.
This module centralizes those calls so handlers don't re-implement
URL formatting or error translation.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class LoginResult:
    access_token: str
    refresh_token: str
    expires_in: int
    must_change_password: bool


class AuthClientError(Exception):
    """Auth call failed for reasons other than bad credentials."""


class InvalidCredentials(Exception):
    """Auth rejected the login as invalid credentials."""


async def login(base_url: str, email: str, password: str) -> LoginResult:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{base_url}/auth/login",
            json={"email": email, "password": password},
        )
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
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{base_url}/auth/password/change",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": current_password, "new_password": new_password},
        )
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
