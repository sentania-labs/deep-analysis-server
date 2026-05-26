"""Thin HTTP client over the internal parser service.

The web service calls parser directly over the backend compose network
(``http://parser:8000``) rather than looping through the Caddy gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from web_service.http_helper import raw_request


class ParserClientError(Exception):
    """Parser call failed for transport, 5xx, or unexpected non-2xx."""


class ParserForbidden(Exception):
    """Parser rejected the request as 401/403."""


class ParserRateLimited(Exception):
    """Parser rejected a self-service reparse as rate-limited (429).

    Carries the structured detail payload so the web layer can render a
    friendly "try again at HH:MM" message instead of a generic 503.
    """

    def __init__(self, retry_after_seconds: int, retry_at: str) -> None:
        super().__init__(f"rate_limited; retry_at={retry_at}")
        self.retry_after_seconds = retry_after_seconds
        self.retry_at = retry_at


# Shorthand kwargs for all parser helpers.
_ERR_RAW = {"error_cls": ParserClientError}


@dataclass
class DeletedCountResult:
    deleted_count: int


async def delete_my_matches(
    base_url: str,
    token: str,
    *,
    agent_id: str | None = None,
) -> DeletedCountResult:
    """Delete parsed matches for the authenticated user.

    When *agent_id* is provided, only matches uploaded by that agent
    are deleted.  Returns the count of deleted matches.
    """
    params: dict[str, str] = {}
    if agent_id is not None:
        params["agent_id"] = agent_id
    resp = await raw_request(
        "DELETE",
        f"{base_url}/parser/matches",
        token=token,
        timeout=30.0,
        params=params,
        error_prefix="parser DELETE /parser/matches ",
        **_ERR_RAW,
    )
    if resp.status_code in (401, 403):
        raise ParserForbidden(f"parser DELETE /parser/matches returned {resp.status_code}")
    if resp.status_code >= 400:
        raise ParserClientError(
            f"parser DELETE /parser/matches returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return DeletedCountResult(deleted_count=int(data.get("deleted_count", 0)))


async def admin_delete_all_matches(
    base_url: str,
    token: str,
) -> DeletedCountResult:
    """Admin nuclear: delete ALL parsed matches across all users."""
    resp = await raw_request(
        "DELETE",
        f"{base_url}/parser/admin/matches",
        token=token,
        timeout=60.0,
        error_prefix="parser DELETE /parser/admin/matches ",
        **_ERR_RAW,
    )
    if resp.status_code in (401, 403):
        raise ParserForbidden(f"parser DELETE /parser/admin/matches returned {resp.status_code}")
    if resp.status_code >= 400:
        raise ParserClientError(
            f"parser DELETE /parser/admin/matches returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return DeletedCountResult(deleted_count=int(data.get("deleted_count", 0)))


async def admin_delete_user_matches(
    base_url: str,
    token: str,
    user_id: int,
    *,
    agent_id: str | None = None,
) -> DeletedCountResult:
    """Admin: delete parsed matches for a specific user.

    When *agent_id* is provided, only matches uploaded by that agent
    are deleted.
    """
    params: dict[str, str] = {}
    if agent_id is not None:
        params["agent_id"] = agent_id
    resp = await raw_request(
        "DELETE",
        f"{base_url}/parser/admin/matches/{user_id}",
        token=token,
        timeout=30.0,
        params=params,
        error_prefix=f"parser DELETE /parser/admin/matches/{user_id} ",
        **_ERR_RAW,
    )
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


async def user_self_service_reparse(
    base_url: str,
    token: str,
) -> DeletedCountResult:
    """POST /parser/me/reparse — reparse all of the caller's matches.

    Raises :class:`ParserRateLimited` on 429 with retry-after metadata
    so the web layer can render a "try again at HH:MM" message.
    """
    resp = await raw_request(
        "POST",
        f"{base_url}/parser/me/reparse",
        token=token,
        timeout=30.0,
        error_prefix="parser POST /parser/me/reparse ",
        **_ERR_RAW,
    )
    if resp.status_code in (401, 403):
        raise ParserForbidden(f"parser POST /parser/me/reparse returned {resp.status_code}")
    if resp.status_code == 429:
        try:
            detail = resp.json().get("detail") or {}
        except ValueError:
            detail = {}
        if not isinstance(detail, dict):
            detail = {}
        raise ParserRateLimited(
            retry_after_seconds=int(detail.get("retry_after_seconds", 0)),
            retry_at=str(detail.get("retry_at", "")),
        )
    if resp.status_code >= 400:
        raise ParserClientError(
            f"parser POST /parser/me/reparse returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return DeletedCountResult(deleted_count=int(data.get("deleted_count", 0)))
