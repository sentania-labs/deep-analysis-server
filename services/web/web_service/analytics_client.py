"""Thin HTTP client over the internal analytics service.

The web service calls analytics directly over the backend compose
network (``http://analytics:8000``) for the admin archetype-catalog
CRUD pages. Mirrors the structure of :mod:`web_service.auth_client` —
same exception types so handlers can keep their existing
AuthForbidden / AuthClientError branches.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx


@dataclass
class ArchetypeItem:
    id: str
    name: str
    format: str
    defining_cards: list[str]
    sample_decklists: list[Any] | None
    created_at: datetime | None
    updated_at: datetime | None


class AnalyticsClientError(Exception):
    """Analytics call failed for transport, 5xx, or unexpected non-2xx."""


class AnalyticsForbidden(Exception):
    """Analytics rejected the request as 401/403."""


def _parse_dt(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _to_item(payload: dict[str, Any]) -> ArchetypeItem:
    return ArchetypeItem(
        id=str(payload["id"]),
        name=str(payload["name"]),
        format=str(payload["format"]),
        defining_cards=list(payload.get("defining_cards") or []),
        sample_decklists=payload.get("sample_decklists"),
        created_at=_parse_dt(payload.get("created_at")),
        updated_at=_parse_dt(payload.get("updated_at")),
    )


async def admin_list_archetypes(
    base_url: str,
    token: str,
) -> tuple[list[ArchetypeItem], int]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/archetypes",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /archetypes transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /archetypes returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /archetypes returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    items = [_to_item(a) for a in data.get("archetypes", [])]
    return items, int(data.get("total", len(items)))


async def admin_get_archetype(
    base_url: str,
    token: str,
    archetype_id: str,
) -> ArchetypeItem | None:
    """Fetch a single archetype. Returns None on 404."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/archetypes/{archetype_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /archetypes/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 404:
        return None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /archetypes/{{id}} returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /archetypes/{{id}} returned {resp.status_code}: {resp.text}"
        )
    return _to_item(resp.json())


async def admin_create_archetype(
    base_url: str,
    token: str,
    *,
    name: str,
    format_: str,
    defining_cards: list[str],
) -> tuple[ArchetypeItem | None, str | None]:
    """Create. Returns (item, None) on success; (None, error_code) on 4xx."""
    body = {
        "name": name,
        "format": format_,
        "defining_cards": defining_cards,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/archetypes",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics POST /archetypes transport error: {exc}") from exc
    if resp.status_code in (200, 201):
        return _to_item(resp.json()), None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics POST /archetypes returned {resp.status_code}")
    if resp.status_code in (400, 422):
        return None, "invalid_input"
    raise AnalyticsClientError(
        f"analytics POST /archetypes returned {resp.status_code}: {resp.text}"
    )


async def admin_update_archetype(
    base_url: str,
    token: str,
    archetype_id: str,
    *,
    name: str,
    format_: str,
    defining_cards: list[str],
) -> tuple[ArchetypeItem | None, str | None]:
    body = {
        "name": name,
        "format": format_,
        "defining_cards": defining_cards,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(
                f"{base_url}/analytics/archetypes/{archetype_id}",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics PUT /archetypes/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 200:
        return _to_item(resp.json()), None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics PUT /archetypes/{{id}} returned {resp.status_code}")
    if resp.status_code == 404:
        return None, "archetype_not_found"
    if resp.status_code in (400, 422):
        return None, "invalid_input"
    raise AnalyticsClientError(
        f"analytics PUT /archetypes/{{id}} returned {resp.status_code}: {resp.text}"
    )


async def admin_delete_archetype(
    base_url: str,
    token: str,
    archetype_id: str,
) -> tuple[bool, str | None]:
    """Delete. (True, None) on 204, (False, code) on 404."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(
                f"{base_url}/analytics/archetypes/{archetype_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics DELETE /archetypes/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics DELETE /archetypes/{{id}} returned {resp.status_code}")
    if resp.status_code == 404:
        return False, "archetype_not_found"
    raise AnalyticsClientError(
        f"analytics DELETE /archetypes/{{id}} returned {resp.status_code}: {resp.text}"
    )
