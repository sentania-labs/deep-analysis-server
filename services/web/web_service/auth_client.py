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


@dataclass
class AdminAgentItem:
    agent_id: str
    user_id: int
    user_email: str
    machine_name: str
    client_version: str | None
    created_at: datetime | None
    last_seen_at: datetime | None
    revoked_at: datetime | None


@dataclass
class UserItem:
    id: int
    email: str
    role: str
    disabled: bool
    must_change_password: bool
    created_at: datetime | None
    updated_at: datetime | None


@dataclass
class UpdateMeResult:
    """Result of PATCH /auth/me. On success, carries the rotated
    access token + ttl so the web layer can refresh the session
    cookie without forcing the user to re-login.
    """

    ok: bool
    error: str | None = None
    access_token: str | None = None
    expires_in: int | None = None


class AuthClientError(Exception):
    """Auth call failed for transport, 5xx, or unexpected non-2xx."""


class InvalidCredentials(Exception):
    """Auth rejected the login as invalid credentials."""


class AuthForbidden(Exception):
    """Auth rejected the request as 401/403.

    Distinct from :class:`AuthClientError` so callers can differentiate a
    revoked/demoted admin (browser session JWT still carries an ``admin``
    claim, but auth's DB no longer agrees) from a real backend outage.
    """


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

    On 204, returns (True, None). On a 400 validation failure, returns
    (False, <error-code-from-auth>) so the caller can render an inline
    message. 401/403 raise :class:`AuthForbidden` — the session is no
    longer accepted by auth (revoked, expired, or current password
    rejected) and the caller must re-authenticate.
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
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /password/change returned {resp.status_code}")
    if resp.status_code == 400:
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
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /me returned {resp.status_code}")
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
) -> tuple[list[AgentItem], int]:
    """List the caller's own agents.

    Returns ``(items, total)`` so the web layer can render pagination
    controls. ``total`` is the unfiltered count of the caller's agents
    (matches the auth-side ``AgentListView.total``).
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/auth/me/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "offset": offset},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /me/agents transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /me/agents returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AuthClientError(f"auth /me/agents returned {resp.status_code}: {resp.text}")
    data = resp.json()
    items = [
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
    return items, int(data.get("total", len(items)))


async def update_me(
    base_url: str,
    token: str,
    email: str,
) -> UpdateMeResult:
    """Try to update the caller's email.

    On 200, returns ``UpdateMeResult(ok=True, access_token=..., expires_in=...)``
    — the auth response carries a freshly-minted token because email is a
    JWT claim and the caller's existing token is now stale.

    Maps known error responses to UI-stable error codes:
      - 409 (email_already_exists) → ``UpdateMeResult(ok=False, error="email_taken")``
      - 400/422 → ``UpdateMeResult(ok=False, error="invalid_email")``

    401/403 raise :class:`AuthForbidden`; 5xx / transport raise
    :class:`AuthClientError`.
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
        data = resp.json()
        return UpdateMeResult(
            ok=True,
            error=None,
            access_token=str(data["access_token"]),
            expires_in=int(data["expires_in"]),
        )
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /me PATCH returned {resp.status_code}")
    if resp.status_code == 409:
        return UpdateMeResult(ok=False, error="email_taken")
    if resp.status_code in (400, 422):
        return UpdateMeResult(ok=False, error="invalid_email")
    raise AuthClientError(f"auth /me PATCH returned {resp.status_code}: {resp.text}")


async def revoke_my_agent(
    base_url: str,
    token: str,
    agent_id: str,
) -> tuple[bool, str | None]:
    """Try to revoke one of the caller's own agents. Returns (ok, error_code).

    - 204 → (True, None)
    - 404 → (False, "not_found")

    401/403 raise :class:`AuthForbidden`; 5xx / transport raise
    :class:`AuthClientError`.
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
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /me/agents revoke returned {resp.status_code}")
    if resp.status_code == 404:
        return False, "not_found"
    raise AuthClientError(f"auth /me/agents revoke returned {resp.status_code}: {resp.text}")


async def admin_list_users(
    base_url: str,
    token: str,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[UserItem], int]:
    """Admin-only: list all users via the auth service.

    Returns ``(items, total)``. Raises :class:`AuthForbidden` on 401/403
    (caller's session/role no longer satisfies auth's check) and
    :class:`AuthClientError` on transport / 5xx / other non-2xx so the
    web layer can render an admin-denied page vs. a service-outage page.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/admin/users",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "offset": offset},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /admin/users transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /admin/users returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AuthClientError(f"auth /admin/users returned {resp.status_code}: {resp.text}")
    data = resp.json()
    items = [
        UserItem(
            id=int(u["id"]),
            email=str(u["email"]),
            role=str(u["role"]),
            disabled=bool(u["disabled"]),
            must_change_password=bool(u["must_change_password"]),
            created_at=_parse_dt(u.get("created_at")),
            updated_at=_parse_dt(u.get("updated_at")),
        )
        for u in data.get("users", [])
    ]
    return items, int(data.get("total", len(items)))


async def admin_delete_user(
    base_url: str,
    token: str,
    user_id: int,
) -> tuple[bool, str | None]:
    """Admin-only: delete a user via the auth service.

    - 204 → (True, None)
    - 400 with detail.error ∈ {cannot_delete_self, cannot_delete_last_admin} → (False, code)
    - 404 → (False, "user_not_found")
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(
                f"{base_url}/admin/users/{user_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth DELETE /admin/users transport error: {exc}") from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth DELETE /admin/users returned {resp.status_code}")
    if resp.status_code in (400, 404):
        try:
            detail = resp.json().get("detail") or {}
            code = detail.get("error") if isinstance(detail, dict) else None
        except ValueError:
            code = None
        return False, code or "delete_failed"
    raise AuthClientError(f"auth DELETE /admin/users returned {resp.status_code}: {resp.text}")


async def admin_list_agents(
    base_url: str,
    token: str,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AdminAgentItem], int]:
    """Admin-only: list every agent across every user.

    Mirrors :func:`admin_list_users`: ``(items, total)`` for pagination,
    :class:`AuthForbidden` on 401/403 (revoked/demoted admin) and
    :class:`AuthClientError` on transport / 5xx so the web layer can
    distinguish the admin-denied page from a service-outage page.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/admin/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "offset": offset},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /admin/agents transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /admin/agents returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AuthClientError(f"auth /admin/agents returned {resp.status_code}: {resp.text}")
    data = resp.json()
    items = [
        AdminAgentItem(
            agent_id=str(a["agent_id"]),
            user_id=int(a["user_id"]),
            user_email=str(a["user_email"]),
            machine_name=str(a["machine_name"]),
            client_version=a.get("client_version"),
            created_at=_parse_dt(a.get("created_at")),
            last_seen_at=_parse_dt(a.get("last_seen_at")),
            revoked_at=_parse_dt(a.get("revoked_at")),
        )
        for a in data.get("agents", [])
    ]
    return items, int(data.get("total", len(items)))


async def admin_revoke_agent(
    base_url: str,
    token: str,
    agent_id: str,
) -> tuple[bool, str | None]:
    """Admin-only: revoke any agent regardless of ownership.

    - 204 → (True, None)
    - 404 → (False, "agent_not_found")

    401/403 raise :class:`AuthForbidden`; transport / 5xx raise
    :class:`AuthClientError`.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/admin/agents/{agent_id}/revoke",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /admin/agents revoke transport error: {exc}") from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /admin/agents revoke returned {resp.status_code}")
    if resp.status_code == 404:
        return False, "agent_not_found"
    raise AuthClientError(f"auth /admin/agents revoke returned {resp.status_code}: {resp.text}")


@dataclass
class RegistrationMode:
    mode: str  # "open" | "invite_only"
    updated_at: datetime | None
    updated_by_user_id: int | None


async def admin_get_registration_mode(
    base_url: str,
    token: str,
) -> RegistrationMode:
    """Admin-only: read the current registration mode.

    Any admin may read; raises :class:`AuthForbidden` on 401/403 (a
    non-admin or revoked-admin caller) and :class:`AuthClientError` on
    transport / 5xx so the web layer can distinguish the admin-denied
    page from a service-outage page.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/admin/settings/registration-mode",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(
            f"auth /admin/settings/registration-mode transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /admin/settings/registration-mode returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AuthClientError(
            f"auth /admin/settings/registration-mode returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return RegistrationMode(
        mode=str(data["mode"]),
        updated_at=_parse_dt(data.get("updated_at")),
        updated_by_user_id=(
            int(data["updated_by_user_id"]) if data.get("updated_by_user_id") is not None else None
        ),
    )


async def admin_set_registration_mode(
    base_url: str,
    token: str,
    mode: str,
) -> tuple[RegistrationMode | None, str | None]:
    """Root-admin-only: flip the registration mode. Returns (view, error_code).

    - 200 → (RegistrationMode, None)
    - 403 with detail.error == "not_root_admin" → (None, "not_root_admin")
      (caller is admin but not UID=1 — surfaces inline rather than
      bouncing to /login; the page still renders for read-only admins)
    - 422 / other 4xx with a validation-style detail → (None, "invalid_mode")

    Any other 401/403 raises :class:`AuthForbidden`; 5xx / transport
    raise :class:`AuthClientError`.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(
                f"{base_url}/admin/settings/registration-mode",
                headers={"Authorization": f"Bearer {token}"},
                json={"mode": mode},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(
            f"auth PUT /admin/settings/registration-mode transport error: {exc}"
        ) from exc
    if resp.status_code == 200:
        data = resp.json()
        return RegistrationMode(
            mode=str(data["mode"]),
            updated_at=_parse_dt(data.get("updated_at")),
            updated_by_user_id=(
                int(data["updated_by_user_id"])
                if data.get("updated_by_user_id") is not None
                else None
            ),
        ), None
    if resp.status_code == 403:
        try:
            detail = resp.json().get("detail") or {}
            code = detail.get("error") if isinstance(detail, dict) else None
        except ValueError:
            code = None
        if code == "not_root_admin":
            return None, "not_root_admin"
        raise AuthForbidden("auth PUT /admin/settings/registration-mode returned 403")
    if resp.status_code == 401:
        raise AuthForbidden("auth PUT /admin/settings/registration-mode returned 401")
    if resp.status_code in (400, 422):
        return None, "invalid_mode"
    raise AuthClientError(
        f"auth PUT /admin/settings/registration-mode returned {resp.status_code}: {resp.text}"
    )


@dataclass
class InviteItem:
    id: str
    created_by_user_id: int | None
    created_by_email: str | None
    created_at: datetime | None
    expires_at: datetime | None


@dataclass
class CreatedInvite:
    id: str
    token: str
    expires_at: datetime | None
    created_at: datetime | None


async def admin_create_invite(
    base_url: str,
    token: str,
    expires_in_hours: int,
) -> CreatedInvite:
    """Admin-only: mint a new invite token.

    Returns the plaintext token + metadata. Surface-level errors
    (validation 422 etc.) raise :class:`AuthClientError` — the inline
    form already constrains the input, so a 422 here is unexpected and
    deserves to bubble up.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/admin/invites",
                headers={"Authorization": f"Bearer {token}"},
                json={"expires_in_hours": expires_in_hours},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth POST /admin/invites transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth POST /admin/invites returned {resp.status_code}")
    if resp.status_code != 201:
        raise AuthClientError(f"auth POST /admin/invites returned {resp.status_code}: {resp.text}")
    data = resp.json()
    return CreatedInvite(
        id=str(data["id"]),
        token=str(data["token"]),
        expires_at=_parse_dt(data.get("expires_at")),
        created_at=_parse_dt(data.get("created_at")),
    )


async def admin_list_invites(
    base_url: str,
    token: str,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[InviteItem], int]:
    """Admin-only: list pending (unused, unexpired) invites."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/admin/invites",
                headers={"Authorization": f"Bearer {token}"},
                params={"page": page, "per_page": per_page},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth GET /admin/invites transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth GET /admin/invites returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AuthClientError(f"auth GET /admin/invites returned {resp.status_code}: {resp.text}")
    data = resp.json()
    items = [
        InviteItem(
            id=str(i["id"]),
            created_by_user_id=(
                int(i["created_by_user_id"]) if i.get("created_by_user_id") is not None else None
            ),
            created_by_email=i.get("created_by_email"),
            created_at=_parse_dt(i.get("created_at")),
            expires_at=_parse_dt(i.get("expires_at")),
        )
        for i in data.get("invites", [])
    ]
    return items, int(data.get("total", len(items)))


async def admin_revoke_invite(
    base_url: str,
    token: str,
    invite_id: str,
) -> tuple[bool, str | None]:
    """Admin-only: revoke a pending invite. Returns (ok, error_code)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(
                f"{base_url}/admin/invites/{invite_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth DELETE /admin/invites transport error: {exc}") from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth DELETE /admin/invites returned {resp.status_code}")
    if resp.status_code == 404:
        return False, "invite_not_found"
    raise AuthClientError(f"auth DELETE /admin/invites returned {resp.status_code}: {resp.text}")


async def public_get_registration_mode(base_url: str) -> str:
    """Public read of the current registration mode.

    Returns ``"open"`` or ``"invite_only"``. Falls back to
    ``"invite_only"`` (the safer default) on transport / 5xx so a flaky
    auth instance defaults to lock-down rather than letting strangers
    sign up.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/auth/registration-mode")
    except httpx.HTTPError:
        return "invite_only"
    if resp.status_code != 200:
        return "invite_only"
    try:
        mode = str(resp.json().get("mode") or "")
    except ValueError:
        return "invite_only"
    return mode if mode in ("open", "invite_only") else "invite_only"


async def public_register(
    base_url: str,
    email: str,
    password: str,
    invite_token: str | None,
) -> tuple[bool, str | None]:
    """Public registration. Returns (ok, error_code).

    Maps known auth-side error codes through to the caller for inline
    rendering — invite_required, invalid_invite_token, weak_password,
    email_already_exists, invalid_email. Anything else surfaces as
    :class:`AuthClientError`.
    """
    payload: dict[str, Any] = {"email": email, "password": password}
    if invite_token:
        payload["token"] = invite_token
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{base_url}/auth/register", json=payload)
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth POST /auth/register transport error: {exc}") from exc
    if resp.status_code == 201:
        return True, None
    if resp.status_code in (400, 403, 409, 422):
        try:
            detail = resp.json().get("detail") or {}
            code = detail.get("error") if isinstance(detail, dict) else None
        except ValueError:
            code = None
        return False, code or "registration_failed"
    raise AuthClientError(f"auth POST /auth/register returned {resp.status_code}: {resp.text}")


async def admin_reset_password(
    base_url: str,
    token: str,
    user_id: int,
) -> tuple[str | None, str | None]:
    """Admin-only: rotate another user's password.

    Returns ``(temporary_password, error_code)``:
    - 200 → (temp, None)
    - 404 → (None, "user_not_found")
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/admin/users/{user_id}/reset-password",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AuthClientError(f"auth /admin/users reset-password transport error: {exc}") from exc
    if resp.status_code == 200:
        return str(resp.json()["temporary_password"]), None
    if resp.status_code in (401, 403):
        raise AuthForbidden(f"auth /admin/users reset-password returned {resp.status_code}")
    if resp.status_code == 404:
        return None, "user_not_found"
    raise AuthClientError(
        f"auth /admin/users reset-password returned {resp.status_code}: {resp.text}"
    )
