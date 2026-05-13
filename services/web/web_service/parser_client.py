"""Thin HTTP client over the internal parser service.

The web service calls parser directly over the backend compose network
(``http://parser:8000``) rather than looping through the Caddy gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx


class ParserClientError(Exception):
    """Parser call failed for transport, 5xx, or unexpected non-2xx."""


class ParserForbidden(Exception):
    """Parser rejected the request as 401/403."""


@dataclass
class DeletedCountResult:
    deleted_count: int


async def delete_my_matches(
    base_url: str,
    token: str,
) -> DeletedCountResult:
    """Delete all parsed matches for the authenticated user.

    Returns the count of deleted matches.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.delete(
                f"{base_url}/parser/matches",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise ParserClientError(f"parser DELETE /parser/matches transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise ParserForbidden(f"parser DELETE /parser/matches returned {resp.status_code}")
    if resp.status_code >= 400:
        raise ParserClientError(
            f"parser DELETE /parser/matches returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return DeletedCountResult(deleted_count=int(data.get("deleted_count", 0)))


async def admin_delete_user_matches(
    base_url: str,
    token: str,
    user_id: int,
) -> DeletedCountResult:
    """Admin: delete all parsed matches for a specific user."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.delete(
                f"{base_url}/parser/admin/matches/{user_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise ParserClientError(
            f"parser DELETE /parser/admin/matches/{user_id} transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise ParserForbidden(
            f"parser DELETE /parser/admin/matches/{user_id} returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise ParserClientError(
            f"parser DELETE /parser/admin/matches/{user_id}"
            f" returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return DeletedCountResult(deleted_count=int(data.get("deleted_count", 0)))
