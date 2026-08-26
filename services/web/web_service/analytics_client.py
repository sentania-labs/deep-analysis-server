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

from web_service.http_helper import parse_dt as _parse_dt
from web_service.http_helper import raw_request, request


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


class AnalyticsConflict(Exception):
    """Analytics rejected the request as 409 (a run is already active)."""

    def __init__(self, message: str, payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.payload = payload or {}


# Shorthand kwargs for all analytics helpers.
_ERR = {"error_cls": AnalyticsClientError, "forbidden_cls": AnalyticsForbidden}
_ERR_RAW = {"error_cls": AnalyticsClientError}


def _conflict_payload(resp: Any) -> dict[str, Any]:
    """Best-effort decode of a 409 body; analytics ships JSON, but a
    proxy in the way might not."""
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


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
    resp = await request(
        "GET",
        f"{base_url}/analytics/archetypes",
        token=token,
        error_prefix="analytics GET /archetypes ",
        **_ERR,
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
    resp = await raw_request(
        "GET",
        f"{base_url}/analytics/archetypes/{archetype_id}",
        token=token,
        error_prefix="analytics GET /archetypes/{id} ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "POST",
        f"{base_url}/analytics/archetypes",
        token=token,
        json=body,
        error_prefix="analytics POST /archetypes ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "PUT",
        f"{base_url}/analytics/archetypes/{archetype_id}",
        token=token,
        json=body,
        error_prefix="analytics PUT /archetypes/{id} ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "DELETE",
        f"{base_url}/analytics/archetypes/{archetype_id}",
        token=token,
        error_prefix="analytics DELETE /archetypes/{id} ",
        **_ERR_RAW,
    )
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/summary",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/summary ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/by-format",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/by-format ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/cards",
        token=token,
        params={"q": q},
        error_prefix="analytics GET /cards ",
        **_ERR,
    )
    return [_to_card(row) for row in resp.json()]


# ---------------------------------------------------------------------------
# Admin cards
# ---------------------------------------------------------------------------


async def admin_get_cards_status(base_url: str, token: str) -> dict[str, Any]:
    resp = await request(
        "GET",
        f"{base_url}/analytics/admin/cards-status",
        token=token,
        error_prefix="analytics GET /admin/cards-status ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/admin/scraper-health",
        token=token,
        params={"scraper_name": scraper_name},
        error_prefix="analytics GET /admin/scraper-health ",
        **_ERR,
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
        "is_running": bool(payload.get("is_running")),
        "running_since": _parse_dt(payload.get("running_since")),
        "run_trigger": payload.get("run_trigger"),
    }


async def admin_get_all_scraper_health(base_url: str, token: str) -> list[dict[str, Any]]:
    """Fetch health for all registered scrapers (v0.9.4+)."""
    resp = await request(
        "GET",
        f"{base_url}/analytics/admin/scraper-health",
        token=token,
        error_prefix="analytics GET /admin/scraper-health ",
        **_ERR,
    )
    payload = resp.json()
    scrapers = payload.get("scrapers")
    if isinstance(scrapers, list):
        return [_parse_scraper_health(s) for s in scrapers]
    # Backward compat: if the endpoint returns a single scraper dict
    return [_parse_scraper_health(payload)]


async def admin_trigger_mtgtop8_scrape(base_url: str, token: str) -> bool:
    """Trigger an mtgtop8 results scrape. Returns True on 202."""
    resp = await raw_request(
        "POST",
        f"{base_url}/analytics/admin/scrape-mtgtop8",
        token=token,
        error_prefix="analytics POST /admin/scrape-mtgtop8 ",
        **_ERR_RAW,
    )
    if resp.status_code == 202:
        return True
    if resp.status_code == 409:
        raise AnalyticsConflict(
            "analytics POST /admin/scrape-mtgtop8 returned 409",
            _conflict_payload(resp),
        )
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
    resp = await request(
        "POST",
        f"{base_url}/analytics/admin/scraper-health/reset",
        token=token,
        params={"scraper_name": scraper_name},
        error_prefix="analytics POST /admin/scraper-health/reset ",
        **_ERR,
    )
    return _parse_scraper_health(resp.json())


async def admin_trigger_sync(base_url: str, token: str) -> bool:
    """Kick off a card sync. Returns True on 202 (sync scheduled)."""
    resp = await raw_request(
        "POST",
        f"{base_url}/analytics/admin/sync-cards",
        token=token,
        error_prefix="analytics POST /admin/sync-cards ",
        **_ERR_RAW,
    )
    if resp.status_code == 202:
        return True
    if resp.status_code in (401, 403):
        raise AnalyticsForbidden(f"analytics POST /admin/sync-cards returned {resp.status_code}")
    raise AnalyticsClientError(
        f"analytics POST /admin/sync-cards returned {resp.status_code}: {resp.text}"
    )


async def admin_trigger_mtgo_scrape(base_url: str, token: str) -> bool:
    """Trigger an MTGO results scrape. Returns True on 202."""
    resp = await raw_request(
        "POST",
        f"{base_url}/analytics/admin/scrape-mtgo",
        token=token,
        error_prefix="analytics POST /admin/scrape-mtgo ",
        **_ERR_RAW,
    )
    if resp.status_code == 202:
        return True
    if resp.status_code == 409:
        raise AnalyticsConflict(
            "analytics POST /admin/scrape-mtgo returned 409",
            _conflict_payload(resp),
        )
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
    review_reason: str | None = None


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
        review_reason=payload.get("review_reason"),
    )


async def get_match_detail(base_url: str, token: str, match_id: str) -> MatchDetail | None:
    """Fetch a single match. Returns None on 404."""
    resp = await raw_request(
        "GET",
        f"{base_url}/analytics/matches/{match_id}",
        token=token,
        error_prefix="analytics GET /matches/{id} ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "GET",
        f"{base_url}/analytics/matches/admin/{match_id}",
        token=token,
        error_prefix="analytics GET /matches/admin/{id} ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "PATCH",
        f"{base_url}/analytics/matches/{match_id}/format",
        token=token,
        json={"format": format_},
        error_prefix="analytics PATCH /matches/{id}/format ",
        **_ERR_RAW,
    )
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/matches",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/matches ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/username-suggestion",
        token=token,
        error_prefix="analytics GET /stats/username-suggestion ",
        **_ERR,
    )
    return [
        UsernameSuggestionItem(
            username=str(row.get("username", "")),
            match_count=int(row.get("match_count", 0)),
        )
        for row in resp.json()
    ]


async def get_stats_by_opponent(
    base_url: str,
    token: str,
    *,
    format_filter: str | None = None,
    opponent: str | None = None,
    result: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[OpponentStatItem]:
    """Per-opponent aggregates, optionally narrowed by the Match History filters.

    Same filter vocabulary as :func:`get_match_list` so the two halves of
    the page describe the same set of matches (issue #124).
    """
    params: dict[str, Any] = {}
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/by-opponent",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/by-opponent ",
        **_ERR,
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
    review_reason: str | None = None


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
        review_reason=payload.get("review_reason"),
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/admin/matches",
        token=token,
        params=params,
        error_prefix="analytics GET /admin/matches ",
        **_ERR,
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
    resp = await raw_request(
        "POST",
        f"{base_url}/analytics/admin/matches/{match_id}/review",
        token=token,
        json=body,
        error_prefix="analytics POST /admin/matches/{id}/review ",
        **_ERR_RAW,
    )
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/play-draw",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/play-draw ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/preboard-postboard",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/preboard-postboard ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/mulligans",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/mulligans ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/game-length",
        token=token,
        error_prefix="analytics GET /stats/game-length ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/cards",
        token=token,
        params=params,
        error_prefix="analytics GET /stats/cards ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/stats/matches/{match_id}/games/{game_number}/turns",
        token=token,
        error_prefix="analytics GET /matches/{id}/games/{n}/turns ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/metagame/formats",
        token=token,
        error_prefix="analytics GET /metagame/formats ",
        **_ERR,
    )
    data = resp.json()
    return list(data.get("formats", []))


async def get_metagame_tiers(
    base_url: str, token: str, format_: str, window: str = "30d"
) -> dict[str, Any]:
    """Fetch archetype tier list for a format."""
    resp = await request(
        "GET",
        f"{base_url}/analytics/metagame/{format_}/tiers",
        token=token,
        params={"window": window},
        error_prefix="analytics GET /metagame/{format}/tiers ",
        **_ERR,
    )
    return dict(resp.json())


async def get_metagame_events(
    base_url: str, token: str, format_: str, page: int = 1, per_page: int = 20
) -> dict[str, Any]:
    """Fetch paginated events for a format."""
    resp = await request(
        "GET",
        f"{base_url}/analytics/metagame/{format_}/events",
        token=token,
        params={"page": page, "per_page": per_page},
        error_prefix="analytics GET /metagame/{format}/events ",
        **_ERR,
    )
    return dict(resp.json())


async def get_metagame_event_detail(
    base_url: str, token: str, format_: str, source: str, event_id: int
) -> dict[str, Any]:
    """Fetch a single event with results and decklists."""
    resp = await raw_request(
        "GET",
        f"{base_url}/analytics/metagame/{format_}/events/{source}/{event_id}",
        token=token,
        error_prefix="analytics GET /metagame/{format}/events/{source}/{id} ",
        **_ERR_RAW,
    )
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/metagame/{format_}/trends",
        token=token,
        params={"window": window},
        error_prefix="analytics GET /metagame/{format}/trends ",
        **_ERR,
    )
    return dict(resp.json())


# ---------------------------------------------------------------------------
# Scraper admin dashboard (F13)
# ---------------------------------------------------------------------------


async def admin_get_scrapers(base_url: str, token: str) -> list[dict[str, Any]]:
    """Fetch all scrapers with config + health."""
    resp = await request(
        "GET",
        f"{base_url}/analytics/admin/scrapers",
        token=token,
        error_prefix="analytics GET /admin/scrapers ",
        **_ERR,
    )
    data = resp.json()
    scrapers = data.get("scrapers", [])
    # Normalize datetime strings
    for s in scrapers:
        s["last_run_at"] = _parse_dt(s.get("last_run_at"))
        s["last_success_at"] = _parse_dt(s.get("last_success_at"))
        s["is_running"] = bool(s.get("is_running"))
        s["running_since"] = _parse_dt(s.get("running_since"))
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
    resp = await request(
        "PATCH",
        f"{base_url}/analytics/admin/scrapers/{name}",
        token=token,
        json=body,
        error_prefix="analytics PATCH /admin/scrapers/{name} ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/admin/scrapers/{name}/events",
        token=token,
        params={"page": page, "per_page": per_page},
        error_prefix="analytics GET /admin/scrapers/{name}/events ",
        **_ERR,
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
    resp = await request(
        "GET",
        f"{base_url}/analytics/bnr-events",
        token=token,
        error_prefix="analytics GET /bnr-events ",
        **_ERR,
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
    resp = await raw_request(
        "GET",
        f"{base_url}/analytics/bnr-events/{event_id}",
        token=token,
        error_prefix="analytics GET /bnr-events/{id} ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "POST",
        f"{base_url}/analytics/bnr-events",
        token=token,
        json=body,
        error_prefix="analytics POST /bnr-events ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "PUT",
        f"{base_url}/analytics/bnr-events/{event_id}",
        token=token,
        json=body,
        error_prefix="analytics PUT /bnr-events/{id} ",
        **_ERR_RAW,
    )
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
    resp = await raw_request(
        "DELETE",
        f"{base_url}/analytics/bnr-events/{event_id}",
        token=token,
        error_prefix="analytics DELETE /bnr-events/{id} ",
        **_ERR_RAW,
    )
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
    resp = await request(
        "POST",
        f"{base_url}/analytics/bnr-events/import-wiki",
        token=token,
        timeout=60.0,
        error_prefix="analytics POST /bnr-events/import-wiki ",
        **_ERR,
    )
    return dict(resp.json())


async def get_bnr_events_by_format(base_url: str, token: str, format_: str) -> list[BnrEventItem]:
    """Non-admin: fetch BNR events for a specific format (dashboard use)."""
    resp = await request(
        "GET",
        f"{base_url}/analytics/bnr-events/by-format",
        token=token,
        params={"format": format_},
        error_prefix="analytics GET /bnr-events/by-format ",
        **_ERR,
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
    resp = await raw_request(
        "GET",
        f"{base_url}/analytics/admin/scrapers/{name}/events/{event_id}",
        token=token,
        error_prefix="analytics GET /admin/scrapers/{name}/events/{id} ",
        **_ERR_RAW,
    )
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
