"""Thin HTTP client over the internal analytics service.

The web service calls analytics directly over the backend compose
network (``http://analytics:8000``) for the admin archetype-catalog
CRUD pages and the user stats dashboard. Mirrors the structure of
:mod:`web_service.auth_client` — same exception types so handlers can
keep their existing AuthForbidden / AuthClientError branches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


# ---------------------------------------------------------------------------
# User stats dashboard
# ---------------------------------------------------------------------------


@dataclass
class RecentMatchItem:
    match_id: str
    played_at: datetime | None
    opponent: str | None
    result: str
    format_: str | None
    player_wins: int
    player_losses: int


@dataclass
class StatsSummary:
    total_matches: int
    wins: int
    losses: int
    draws: int
    win_rate: float
    recent_matches: list[RecentMatchItem] = field(default_factory=list)


@dataclass
class FormatStatItem:
    format_: str
    matches: int
    wins: int
    losses: int
    draws: int
    win_rate: float


@dataclass
class OpponentStatItem:
    opponent: str
    matches: int
    wins: int
    losses: int
    draws: int
    win_rate: float


def _to_recent(payload: dict[str, Any]) -> RecentMatchItem:
    return RecentMatchItem(
        match_id=str(payload.get("match_id", "")),
        played_at=_parse_dt(payload.get("played_at")),
        opponent=payload.get("opponent"),
        result=str(payload.get("result") or ""),
        format_=payload.get("format"),
        player_wins=int(payload.get("player_wins") or 0),
        player_losses=int(payload.get("player_losses") or 0),
    )


def _to_summary(payload: dict[str, Any]) -> StatsSummary:
    return StatsSummary(
        total_matches=int(payload.get("total_matches") or 0),
        wins=int(payload.get("wins") or 0),
        losses=int(payload.get("losses") or 0),
        draws=int(payload.get("draws") or 0),
        win_rate=float(payload.get("win_rate") or 0.0),
        recent_matches=[_to_recent(m) for m in payload.get("recent_matches", [])],
    )


def _to_format_stat(payload: dict[str, Any]) -> FormatStatItem:
    return FormatStatItem(
        format_=str(payload.get("format") or "Unknown"),
        matches=int(payload.get("matches") or 0),
        wins=int(payload.get("wins") or 0),
        losses=int(payload.get("losses") or 0),
        draws=int(payload.get("draws") or 0),
        win_rate=float(payload.get("win_rate") or 0.0),
    )


def _to_opponent_stat(payload: dict[str, Any]) -> OpponentStatItem:
    return OpponentStatItem(
        opponent=str(payload.get("opponent") or ""),
        matches=int(payload.get("matches") or 0),
        wins=int(payload.get("wins") or 0),
        losses=int(payload.get("losses") or 0),
        draws=int(payload.get("draws") or 0),
        win_rate=float(payload.get("win_rate") or 0.0),
    )


async def get_stats_summary(
    base_url: str,
    token: str,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
) -> StatsSummary:
    params: dict[str, str] = {}
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/summary",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /stats/summary transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/summary returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/summary returned {resp.status_code}: {resp.text}"
        )
    return _to_summary(resp.json())


async def get_stats_by_format(
    base_url: str,
    token: str,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[FormatStatItem]:
    params: dict[str, str] = {}
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/by-format",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/by-format transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/by-format returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/by-format returned {resp.status_code}: {resp.text}"
        )
    return [_to_format_stat(row) for row in resp.json()]


# ---------------------------------------------------------------------------
# Card search
# ---------------------------------------------------------------------------


@dataclass
class CardItem:
    name: str
    mana_cost: str | None
    type_line: str | None
    oracle_text: str | None
    image_uri: str | None
    set_code: str | None


def _to_card(payload: dict[str, Any]) -> CardItem:
    return CardItem(
        name=str(payload.get("name") or ""),
        mana_cost=payload.get("mana_cost"),
        type_line=payload.get("type_line"),
        oracle_text=payload.get("oracle_text"),
        image_uri=payload.get("image_uri"),
        set_code=payload.get("set_code"),
    )


async def search_cards(base_url: str, token: str, q: str) -> list[CardItem]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/cards",
                params={"q": q},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /cards transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /cards returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(f"analytics GET /cards returned {resp.status_code}: {resp.text}")
    return [_to_card(row) for row in resp.json()]


# ---------------------------------------------------------------------------
# Admin cards
# ---------------------------------------------------------------------------


async def admin_get_cards_status(base_url: str, token: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/cards-status",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /admin/cards-status transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /admin/cards-status returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/cards-status returned {resp.status_code}: {resp.text}"
        )
    payload = resp.json()
    return {
        "card_count": int(payload.get("card_count") or 0),
        "last_sync_at": _parse_dt(payload.get("last_sync_at")),
    }


async def admin_get_scraper_health(
    base_url: str, token: str, scraper_name: str = "mtgo"
) -> dict[str, Any]:
    """Fetch health for a single scraper by name."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/scraper-health",
                params={"scraper_name": scraper_name},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /admin/scraper-health transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /admin/scraper-health returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/scraper-health returned {resp.status_code}: {resp.text}"
        )
    return _parse_scraper_health(resp.json())


def _parse_scraper_health(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a single scraper-health payload dict."""
    return {
        "scraper_name": payload.get("scraper_name"),
        "last_run_at": _parse_dt(payload.get("last_run_at")),
        "last_success_at": _parse_dt(payload.get("last_success_at")),
        "consecutive_failures": int(payload.get("consecutive_failures") or 0),
        "is_broken": bool(payload.get("is_broken")),
        "last_error": payload.get("last_error"),
    }


async def admin_get_all_scraper_health(base_url: str, token: str) -> list[dict[str, Any]]:
    """Fetch health for all registered scrapers (v0.9.4+)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/scraper-health",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /admin/scraper-health transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /admin/scraper-health returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/scraper-health returned {resp.status_code}: {resp.text}"
        )
    payload = resp.json()
    scrapers = payload.get("scrapers")
    if isinstance(scrapers, list):
        return [_parse_scraper_health(s) for s in scrapers]
    # Backward compat: if the endpoint returns a single scraper dict
    return [_parse_scraper_health(payload)]


async def admin_trigger_mtgtop8_scrape(base_url: str, token: str) -> bool:
    """Trigger an mtgtop8 results scrape. Returns True on 202."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/admin/scrape-mtgtop8",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics POST /admin/scrape-mtgtop8 transport error: {exc}"
        ) from exc
    if resp.status_code == 202:
        return True
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics POST /admin/scrape-mtgtop8 returned {resp.status_code}"
        )
    raise AnalyticsClientError(
        f"analytics POST /admin/scrape-mtgtop8 returned {resp.status_code}: {resp.text}"
    )


async def admin_reset_scraper_health(
    base_url: str, token: str, scraper_name: str
) -> dict[str, Any]:
    """Reset a scraper's failure counters."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/admin/scraper-health/reset",
                params={"scraper_name": scraper_name},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics POST /admin/scraper-health/reset transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics POST /admin/scraper-health/reset returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics POST /admin/scraper-health/reset returned {resp.status_code}: {resp.text}"
        )
    return _parse_scraper_health(resp.json())


async def admin_trigger_sync(base_url: str, token: str) -> bool:
    """Kick off a card sync. Returns True on 202 (sync scheduled)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/admin/sync-cards",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics POST /admin/sync-cards transport error: {exc}"
        ) from exc
    if resp.status_code == 202:
        return True
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics POST /admin/sync-cards returned {resp.status_code}")
    raise AnalyticsClientError(
        f"analytics POST /admin/sync-cards returned {resp.status_code}: {resp.text}"
    )


async def admin_trigger_mtgo_scrape(base_url: str, token: str) -> bool:
    """Trigger an MTGO results scrape. Returns True on 202."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/admin/scrape-mtgo",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics POST /admin/scrape-mtgo transport error: {exc}"
        ) from exc
    if resp.status_code == 202:
        return True
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics POST /admin/scrape-mtgo returned {resp.status_code}")
    raise AnalyticsClientError(
        f"analytics POST /admin/scrape-mtgo returned {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# Match detail
# ---------------------------------------------------------------------------


@dataclass
class GameItem:
    game_number: int
    winner: str | None
    turns: int | None
    on_play: bool | None = None
    play_first: str | None = None
    opening_hand_sizes: dict[str, int] | None = None


@dataclass
class MatchDetail:
    match_id: str
    format_: str | None
    players: list[str]
    played_at: datetime | None
    hero_player_name: str | None = None
    games: list[GameItem] = field(default_factory=list)
    review_status: str | None = None


def _to_game(payload: dict[str, Any]) -> GameItem:
    raw_turns = payload.get("turns")
    raw_hand_sizes = payload.get("opening_hand_sizes")
    return GameItem(
        game_number=int(payload.get("game_number") or 0),
        winner=payload.get("winner"),
        turns=int(raw_turns) if raw_turns is not None else None,
        on_play=payload.get("on_play"),
        play_first=payload.get("play_first"),
        opening_hand_sizes=dict(raw_hand_sizes) if raw_hand_sizes else None,
    )


def _to_match_detail(payload: dict[str, Any]) -> MatchDetail:
    return MatchDetail(
        match_id=str(payload.get("match_id") or ""),
        format_=payload.get("format"),
        players=[str(p) for p in (payload.get("players") or [])],
        played_at=_parse_dt(payload.get("played_at")),
        hero_player_name=payload.get("hero_player_name"),
        games=[_to_game(g) for g in (payload.get("games") or [])],
        review_status=payload.get("review_status"),
    )


async def get_match_detail(base_url: str, token: str, match_id: str) -> MatchDetail | None:
    """Fetch a single match. Returns None on 404."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/matches/{match_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /matches/{{id}} transport error: {exc}") from exc
    if resp.status_code == 404:
        return None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /matches/{{id}} returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /matches/{{id}} returned {resp.status_code}: {resp.text}"
        )
    return _to_match_detail(resp.json())


async def admin_get_match_detail(base_url: str, token: str, match_id: str) -> MatchDetail | None:
    """Admin: fetch any match regardless of owner/review status. Returns None on 404."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/matches/admin/{match_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /matches/admin/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 404:
        return None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /matches/admin/{{id}} returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /matches/admin/{{id}} returned {resp.status_code}: {resp.text}"
        )
    return _to_match_detail(resp.json())


async def update_match_format(base_url: str, token: str, match_id: str, format_: str) -> bool:
    """PATCH the format on a match. Returns True on success."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.patch(
                f"{base_url}/analytics/matches/{match_id}/format",
                headers={"Authorization": f"Bearer {token}"},
                json={"format": format_},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics PATCH /matches/{{id}}/format error: {exc}") from exc
    if resp.status_code == 204:
        return True
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics PATCH format returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(f"analytics PATCH format returned {resp.status_code}")
    return True


@dataclass
class MatchListItem:
    match_id: str
    played_at: datetime | None
    opponent: str | None
    result: str
    format_: str | None
    player_wins: int
    player_losses: int


@dataclass
class MatchListResponse:
    matches: list[MatchListItem]
    total: int
    page: int
    per_page: int


def _to_match_list_item(payload: dict[str, Any]) -> MatchListItem:
    return MatchListItem(
        match_id=str(payload.get("match_id", "")),
        played_at=_parse_dt(payload.get("played_at")),
        opponent=payload.get("opponent"),
        result=str(payload.get("result") or ""),
        format_=payload.get("format"),
        player_wins=int(payload.get("player_wins") or 0),
        player_losses=int(payload.get("player_losses") or 0),
    )


async def get_match_list(
    base_url: str,
    token: str,
    *,
    page: int = 1,
    per_page: int = 20,
    format_filter: str | None = None,
    opponent: str | None = None,
    result: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> MatchListResponse:
    params: dict[str, Any] = {"page": page, "per_page": per_page}
    if format_filter and format_filter.lower() != "all":
        params["format"] = format_filter
    if opponent:
        params["opponent"] = opponent
    if result and result.lower() != "all":
        params["result"] = result
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/matches",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /stats/matches transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/matches returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/matches returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return MatchListResponse(
        matches=[_to_match_list_item(m) for m in data.get("matches", [])],
        total=int(data.get("total", 0)),
        page=int(data.get("page", 1)),
        per_page=int(data.get("per_page", 20)),
    )


@dataclass
class UsernameSuggestionItem:
    username: str
    match_count: int


async def get_username_suggestions(base_url: str, token: str) -> list[UsernameSuggestionItem]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/username-suggestion",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/username-suggestion transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /stats/username-suggestion returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/username-suggestion returned {resp.status_code}: {resp.text}"
        )
    return [
        UsernameSuggestionItem(
            username=str(row.get("username", "")),
            match_count=int(row.get("match_count", 0)),
        )
        for row in resp.json()
    ]


async def get_stats_by_opponent(base_url: str, token: str) -> list[OpponentStatItem]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/by-opponent",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/by-opponent transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/by-opponent returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/by-opponent returned {resp.status_code}: {resp.text}"
        )
    return [_to_opponent_stat(row) for row in resp.json()]


# ---------------------------------------------------------------------------
# Admin matches — system-wide match listing
# ---------------------------------------------------------------------------


@dataclass
class AdminMatchItem:
    match_id: str
    user_id: int
    user_email: str | None
    format_: str | None
    players: list[str]
    match_result: str | None
    winner: str | None
    game_count: int
    played_at: datetime | None
    is_draw: bool = False
    review_status: str | None = None


@dataclass
class AdminMatchListResponse:
    matches: list[AdminMatchItem]
    total: int
    page: int
    per_page: int


def _to_admin_match(payload: dict[str, Any]) -> AdminMatchItem:
    return AdminMatchItem(
        match_id=str(payload.get("match_id", "")),
        user_id=int(payload.get("user_id") or 0),
        user_email=payload.get("user_email"),
        format_=payload.get("format"),
        players=[str(p) for p in (payload.get("players") or [])],
        match_result=payload.get("match_result"),
        winner=payload.get("winner"),
        game_count=int(payload.get("game_count") or 0),
        played_at=_parse_dt(payload.get("played_at")),
        is_draw=bool(payload.get("is_draw") or False),
        review_status=payload.get("review_status"),
    )


async def admin_list_matches(
    base_url: str,
    token: str,
    *,
    page: int = 1,
    per_page: int = 20,
    format_filter: str | None = None,
    opponent: str | None = None,
    result: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    review_status: str | None = None,
) -> AdminMatchListResponse:
    params: dict[str, Any] = {"page": page, "per_page": per_page}
    if format_filter and format_filter.lower() != "all":
        params["format"] = format_filter
    if opponent:
        params["opponent"] = opponent
    if result and result.lower() != "all":
        params["result"] = result
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    if review_status and review_status.lower() != "all":
        params["review_status"] = review_status
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/matches",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /admin/matches transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /admin/matches returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/matches returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return AdminMatchListResponse(
        matches=[_to_admin_match(m) for m in data.get("matches", [])],
        total=int(data.get("total", 0)),
        page=int(data.get("page", 1)),
        per_page=int(data.get("per_page", 20)),
    )


async def admin_set_match_review_status(
    base_url: str,
    token: str,
    match_id: str,
    review_status: str | None,
) -> tuple[AdminMatchItem | None, str | None]:
    """Set the holding-pen verdict on a match.

    ``review_status`` may be ``None`` (accept), ``'pending_review'``
    (flag for review), or ``'rejected'`` (permanently discard). Returns
    ``(item, None)`` on success, ``(None, "match_not_found")`` on 404,
    or ``(None, "invalid_review_status")`` on 422.
    """
    body = {"review_status": review_status}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/admin/matches/{match_id}/review",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics POST /admin/matches/{{id}}/review transport error: {exc}"
        ) from exc
    if resp.status_code == 200:
        return _to_admin_match(resp.json()), None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics POST /admin/matches/{{id}}/review returned {resp.status_code}"
        )
    if resp.status_code == 404:
        return None, "match_not_found"
    if resp.status_code in (400, 422):
        return None, "invalid_review_status"
    raise AnalyticsClientError(
        f"analytics POST /admin/matches/{{id}}/review returned {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# v0.9.0 — game-level analytics
# ---------------------------------------------------------------------------


@dataclass
class PlayDrawStats:
    on_play_matches: int
    on_play_wins: int
    on_play_win_rate: float
    on_draw_matches: int
    on_draw_wins: int
    on_draw_win_rate: float


async def get_play_draw_stats(
    base_url: str,
    token: str,
    *,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> PlayDrawStats:
    params: dict[str, str] = {}
    if format_filter:
        params["format"] = format_filter
    if opponent:
        params["opponent"] = opponent
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/play-draw",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/play-draw transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/play-draw returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/play-draw returned {resp.status_code}: {resp.text}"
        )
    d = resp.json()
    on_play = d.get("on_play") or {}
    on_draw = d.get("on_draw") or {}
    return PlayDrawStats(
        on_play_matches=int(on_play.get("total") or 0),
        on_play_wins=int(on_play.get("wins") or 0),
        on_play_win_rate=float(on_play.get("win_rate") or 0.0),
        on_draw_matches=int(on_draw.get("total") or 0),
        on_draw_wins=int(on_draw.get("wins") or 0),
        on_draw_win_rate=float(on_draw.get("win_rate") or 0.0),
    )


@dataclass
class PreboardPostboardStats:
    game1_matches: int
    game1_wins: int
    game1_win_rate: float
    games23_matches: int
    games23_wins: int
    games23_win_rate: float


async def get_preboard_postboard_stats(
    base_url: str,
    token: str,
    *,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> PreboardPostboardStats:
    params: dict[str, str] = {}
    if format_filter:
        params["format"] = format_filter
    if opponent:
        params["opponent"] = opponent
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/preboard-postboard",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/preboard-postboard transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /stats/preboard-postboard returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/preboard-postboard returned {resp.status_code}: {resp.text}"
        )
    d = resp.json()
    preboard = d.get("preboard") or {}
    postboard = d.get("postboard") or {}
    return PreboardPostboardStats(
        game1_matches=int(preboard.get("total") or 0),
        game1_wins=int(preboard.get("wins") or 0),
        game1_win_rate=float(preboard.get("win_rate") or 0.0),
        games23_matches=int(postboard.get("total") or 0),
        games23_wins=int(postboard.get("wins") or 0),
        games23_win_rate=float(postboard.get("win_rate") or 0.0),
    )


@dataclass
class MulliganBucket:
    hand_size: int
    games: int
    wins: int
    win_rate: float


@dataclass
class MulliganStats:
    buckets: list[MulliganBucket]


async def get_mulligan_stats(
    base_url: str,
    token: str,
    *,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> MulliganStats:
    params: dict[str, str] = {}
    if format_filter:
        params["format"] = format_filter
    if opponent:
        params["opponent"] = opponent
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/mulligans",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/mulligans transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/mulligans returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/mulligans returned {resp.status_code}: {resp.text}"
        )
    # The analytics endpoint returns a bare JSON array of MulliganBucket
    # objects (not wrapped in {"buckets": [...]}). Each bucket uses
    # "total" for the game count, which we map to our client's "games".
    raw = resp.json()
    items: list[dict] = raw if isinstance(raw, list) else raw.get("buckets", [])
    buckets = [
        MulliganBucket(
            hand_size=int(b.get("hand_size") or 0),
            games=int(b.get("total") or b.get("games") or 0),
            wins=int(b.get("wins") or 0),
            win_rate=float(b.get("win_rate") or 0.0),
        )
        for b in items
    ]
    return MulliganStats(buckets=buckets)


@dataclass
class GameLengthStats:
    buckets: list[dict[str, Any]]


async def get_game_length_stats(base_url: str, token: str) -> GameLengthStats:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/game-length",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /stats/game-length transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/game-length returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/game-length returned {resp.status_code}: {resp.text}"
        )
    d = resp.json()
    return GameLengthStats(buckets=d.get("buckets", []))


@dataclass
class CardStatItem:
    card_name: str
    games: int
    wins: int
    win_rate: float
    avg_cast_turn: float | None


@dataclass
class CardStatsResponse:
    cards: list[CardStatItem]
    total: int
    page: int
    per_page: int


async def get_card_stats(
    base_url: str,
    token: str,
    *,
    page: int = 1,
    per_page: int = 20,
    sort_by: str = "games",
    sort_dir: str | None = None,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> CardStatsResponse:
    params: dict[str, Any] = {"page": page, "per_page": per_page, "sort_by": sort_by}
    if sort_dir:
        params["sort_dir"] = sort_dir
    if format_filter:
        params["format"] = format_filter
    if opponent:
        params["opponent"] = opponent
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/cards",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /stats/cards transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /stats/cards returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /stats/cards returned {resp.status_code}: {resp.text}"
        )
    d = resp.json()
    cards = [
        CardStatItem(
            card_name=str(c.get("name") or c.get("card_name") or ""),
            games=int(c.get("cast_count") or c.get("games") or 0),
            wins=int(c.get("wins") or 0),
            win_rate=float(c.get("win_rate") or 0.0),
            avg_cast_turn=float(c["avg_cast_turn"]) if c.get("avg_cast_turn") is not None else None,
        )
        for c in d.get("cards", [])
    ]
    return CardStatsResponse(
        cards=cards,
        total=int(d.get("total") or 0),
        page=int(d.get("page") or 1),
        per_page=int(d.get("per_page") or 20),
    )


# ---------------------------------------------------------------------------
# v0.9.0 — turn viewer
# ---------------------------------------------------------------------------


@dataclass
class ZoneState:
    battlefield: list[str] = field(default_factory=list)
    hand: list[str] = field(default_factory=list)
    graveyard: list[str] = field(default_factory=list)
    exile: list[str] = field(default_factory=list)
    library_count: int | None = None


@dataclass
class PlayerTurnState:
    player: str
    life: int | None = None
    zones: ZoneState | None = None


@dataclass
class TurnData:
    turn_number: int
    active_player: str | None
    player_states: list[PlayerTurnState] = field(default_factory=list)
    stack: list[str] = field(default_factory=list)


@dataclass
class GameTurnsResponse:
    match_id: str
    game_number: int
    turns: list[TurnData] = field(default_factory=list)


def _to_zone_state(payload: dict[str, Any] | None) -> ZoneState | None:
    if not payload:
        return None
    return ZoneState(
        battlefield=list(payload.get("battlefield") or []),
        hand=list(payload.get("hand") or []),
        graveyard=list(payload.get("graveyard") or []),
        exile=list(payload.get("exile") or []),
        library_count=(
            int(payload["library_count"]) if payload.get("library_count") is not None else None
        ),
    )


def _to_player_turn_state(payload: dict[str, Any]) -> PlayerTurnState:
    raw_life = payload.get("life")
    return PlayerTurnState(
        player=str(payload.get("player") or ""),
        life=int(raw_life) if raw_life is not None else None,
        zones=_to_zone_state(payload.get("zones")),
    )


def _to_turn(payload: dict[str, Any]) -> TurnData:
    # The analytics endpoint returns player data as a dict keyed by
    # player name (``"players": {"name": {...}}``), while the web
    # client expects a flat list of player state objects.
    raw_states = payload.get("player_states") or []
    if not raw_states:
        players_dict = payload.get("players") or {}
        if isinstance(players_dict, dict):
            raw_states = [
                {"player": name, **(data if isinstance(data, dict) else {})}
                for name, data in players_dict.items()
            ]
    return TurnData(
        turn_number=int(payload.get("turn_number") or 0),
        active_player=payload.get("active_player"),
        player_states=[_to_player_turn_state(ps) for ps in raw_states],
        stack=list(payload.get("stack") or []),
    )


async def get_game_turns(
    base_url: str,
    token: str,
    match_id: str,
    game_number: int,
) -> GameTurnsResponse:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/stats/matches/{match_id}/games/{game_number}/turns",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /matches/{{id}}/games/{{n}}/turns transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /matches/{{id}}/games/{{n}}/turns returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /matches/{{id}}/games/{{n}}/turns "
            f"returned {resp.status_code}: {resp.text}"
        )
    d = resp.json()
    # The analytics endpoint returns either a bare JSON array of turn
    # objects or a wrapped object with match_id/game_number/turns keys.
    if isinstance(d, list):
        turns = [_to_turn(t) for t in d]
    else:
        turns = [_to_turn(t) for t in d.get("turns", [])]
    if isinstance(d, dict):
        resolved_match_id = str(d.get("match_id") or match_id)
        resolved_game_number = int(d.get("game_number") or game_number)
    else:
        resolved_match_id = str(match_id)
        resolved_game_number = game_number
    return GameTurnsResponse(
        match_id=resolved_match_id,
        game_number=resolved_game_number,
        turns=turns,
    )


# ---------------------------------------------------------------------------
# Metagame browser (F11)
# ---------------------------------------------------------------------------


async def get_metagame_formats(base_url: str, token: str) -> list[dict[str, Any]]:
    """Fetch available metagame formats."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/metagame/formats",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /metagame/formats transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /metagame/formats returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /metagame/formats returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return list(data.get("formats", []))


async def get_metagame_tiers(
    base_url: str, token: str, format_: str, window: str = "30d"
) -> dict[str, Any]:
    """Fetch archetype tier list for a format."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/metagame/{format_}/tiers",
                params={"window": window},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/tiers transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /metagame/{{format}}/tiers returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/tiers returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


async def get_metagame_events(
    base_url: str, token: str, format_: str, page: int = 1, per_page: int = 20
) -> dict[str, Any]:
    """Fetch paginated events for a format."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/metagame/{format_}/events",
                params={"page": page, "per_page": per_page},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/events transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /metagame/{{format}}/events returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/events returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


async def get_metagame_event_detail(
    base_url: str, token: str, format_: str, source: str, event_id: int
) -> dict[str, Any]:
    """Fetch a single event with results and decklists."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/metagame/{format_}/events/{source}/{event_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/events/{{source}}/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /metagame/event detail returned {resp.status_code}"
        )
    if resp.status_code == 404:
        return {}
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /metagame/event detail returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


async def get_metagame_trends(
    base_url: str, token: str, format_: str, window: str = "30d"
) -> dict[str, Any]:
    """Fetch trend data for charting archetype popularity over time."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/metagame/{format_}/trends",
                params={"window": window},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/trends transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /metagame/{{format}}/trends returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /metagame/{{format}}/trends returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


# ---------------------------------------------------------------------------
# Scraper admin dashboard (F13)
# ---------------------------------------------------------------------------


async def admin_get_scrapers(base_url: str, token: str) -> list[dict[str, Any]]:
    """Fetch all scrapers with config + health."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/scrapers",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /admin/scrapers transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /admin/scrapers returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/scrapers returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    scrapers = data.get("scrapers", [])
    # Normalize datetime strings
    for s in scrapers:
        s["last_run_at"] = _parse_dt(s.get("last_run_at"))
        s["last_success_at"] = _parse_dt(s.get("last_success_at"))
    return list(scrapers)


async def admin_update_scraper(
    base_url: str,
    token: str,
    name: str,
    *,
    enabled: bool | None = None,
    interval_hours: int | None = None,
) -> dict[str, Any]:
    """Update a scraper's enabled/interval config."""
    body: dict[str, Any] = {}
    if enabled is not None:
        body["enabled"] = enabled
    if interval_hours is not None:
        body["interval_hours"] = interval_hours
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.patch(
                f"{base_url}/analytics/admin/scrapers/{name}",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics PATCH /admin/scrapers/{{name}} transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics PATCH /admin/scrapers/{{name}} returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics PATCH /admin/scrapers/{{name}} returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


async def admin_get_scraper_events(
    base_url: str,
    token: str,
    name: str,
    page: int = 1,
    per_page: int = 20,
) -> dict[str, Any]:
    """Fetch paginated events for a specific scraper."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/scrapers/{name}/events",
                params={"page": page, "per_page": per_page},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /admin/scrapers/{{name}}/events transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /admin/scrapers/{{name}}/events returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/scrapers/{{name}}/events "
            f"returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


# ---------------------------------------------------------------------------
# B&R Events
# ---------------------------------------------------------------------------


@dataclass
class BnrEventItem:
    id: str
    format: str
    effective_date: str  # ISO date string
    description: str
    card_actions: list[dict]
    created_at: datetime | None
    updated_at: datetime | None


def _to_bnr_event(payload: dict[str, Any]) -> BnrEventItem:
    return BnrEventItem(
        id=str(payload["id"]),
        format=str(payload["format"]),
        effective_date=str(payload["effective_date"]),
        description=str(payload["description"]),
        card_actions=list(payload.get("card_actions") or []),
        created_at=_parse_dt(payload.get("created_at")),
        updated_at=_parse_dt(payload.get("updated_at")),
    )


async def admin_list_bnr_events(
    base_url: str,
    token: str,
) -> tuple[list[BnrEventItem], int]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/bnr-events",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics GET /bnr-events transport error: {exc}") from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /bnr-events returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /bnr-events returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    items = [_to_bnr_event(e) for e in data.get("events", [])]
    return items, int(data.get("total", len(items)))


async def admin_get_bnr_event(
    base_url: str,
    token: str,
    event_id: str,
) -> BnrEventItem | None:
    """Fetch a single B&R event. Returns None on 404."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/bnr-events/{event_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /bnr-events/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 404:
        return None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /bnr-events/{{id}} returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /bnr-events/{{id}} returned {resp.status_code}: {resp.text}"
        )
    return _to_bnr_event(resp.json())


async def admin_create_bnr_event(
    base_url: str,
    token: str,
    *,
    format_: str,
    effective_date: str,
    description: str,
    card_actions: list[dict],
) -> tuple[BnrEventItem | None, str | None]:
    """Create. Returns (item, None) on success; (None, error_code) on 4xx."""
    body = {
        "format": format_,
        "effective_date": effective_date,
        "description": description,
        "card_actions": card_actions,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/bnr-events",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(f"analytics POST /bnr-events transport error: {exc}") from exc
    if resp.status_code in (200, 201):
        return _to_bnr_event(resp.json()), None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics POST /bnr-events returned {resp.status_code}")
    if resp.status_code in (400, 422):
        return None, "invalid_input"
    raise AnalyticsClientError(
        f"analytics POST /bnr-events returned {resp.status_code}: {resp.text}"
    )


async def admin_update_bnr_event(
    base_url: str,
    token: str,
    event_id: str,
    *,
    format_: str,
    effective_date: str,
    description: str,
    card_actions: list[dict],
) -> tuple[BnrEventItem | None, str | None]:
    body = {
        "format": format_,
        "effective_date": effective_date,
        "description": description,
        "card_actions": card_actions,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(
                f"{base_url}/analytics/bnr-events/{event_id}",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics PUT /bnr-events/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 200:
        return _to_bnr_event(resp.json()), None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics PUT /bnr-events/{{id}} returned {resp.status_code}")
    if resp.status_code == 404:
        return None, "bnr_event_not_found"
    if resp.status_code in (400, 422):
        return None, "invalid_input"
    raise AnalyticsClientError(
        f"analytics PUT /bnr-events/{{id}} returned {resp.status_code}: {resp.text}"
    )


async def admin_delete_bnr_event(
    base_url: str,
    token: str,
    event_id: str,
) -> tuple[bool, str | None]:
    """Delete. (True, None) on 204, (False, code) on 404."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(
                f"{base_url}/analytics/bnr-events/{event_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics DELETE /bnr-events/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code == 204:
        return True, None
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics DELETE /bnr-events/{{id}} returned {resp.status_code}")
    if resp.status_code == 404:
        return False, "bnr_event_not_found"
    raise AnalyticsClientError(
        f"analytics DELETE /bnr-events/{{id}} returned {resp.status_code}: {resp.text}"
    )


async def admin_import_bnr_wiki(base_url: str, token: str) -> dict[str, Any]:
    """Trigger wiki import. Returns WikiImportResult as dict."""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{base_url}/analytics/bnr-events/import-wiki",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics POST /bnr-events/import-wiki transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics POST /bnr-events/import-wiki returned {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics POST /bnr-events/import-wiki returned {resp.status_code}: {resp.text}"
        )
    return dict(resp.json())


async def get_bnr_events_by_format(base_url: str, token: str, format_: str) -> list[BnrEventItem]:
    """Non-admin: fetch BNR events for a specific format (dashboard use)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/bnr-events/by-format",
                params={"format": format_},
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /bnr-events/by-format transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics GET /bnr-events/by-format returned {resp.status_code}")
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /bnr-events/by-format returned {resp.status_code}: {resp.text}"
        )
    data = resp.json()
    return [_to_bnr_event(e) for e in data.get("events", [])]


async def admin_get_scraper_event_detail(
    base_url: str,
    token: str,
    name: str,
    event_id: int,
) -> dict[str, Any]:
    """Fetch a single event with results for a scraper."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base_url}/analytics/admin/scrapers/{name}/events/{event_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        raise AnalyticsClientError(
            f"analytics GET /admin/scrapers/{{name}}/events/{{id}} transport error: {exc}"
        ) from exc
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(
            f"analytics GET /admin/scrapers/{{name}}/events/{{id}} returned {resp.status_code}"
        )
    if resp.status_code == 404:
        return {}
    if resp.status_code >= 400:
        raise AnalyticsClientError(
            f"analytics GET /admin/scrapers/{{name}}/events/{{id}} returned {resp.status_code}: "
            f"{resp.text}"
        )
    return dict(resp.json())
