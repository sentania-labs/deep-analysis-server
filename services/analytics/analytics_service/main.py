from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from analytics_service.archetypes import router as archetypes_router
from analytics_service.card_stats import router as card_stats_router
from analytics_service.cards import router as cards_router
from analytics_service.db import get_sessionmaker
from analytics_service.deps import AuthenticatedUser, require_admin
from analytics_service.game_stats import router as game_stats_router
from analytics_service.matches import router as matches_router
from analytics_service.metagame import router as metagame_router
from analytics_service.mtgo_scraper import SCRAPER_NAME as MTGO_SCRAPER_NAME
from analytics_service.mtgo_scraper import get_health as get_scraper_health_row
from analytics_service.mtgo_scraper import reset_health as reset_scraper_health_row
from analytics_service.mtgo_scraper import run_scrape as run_mtgo_scrape
from analytics_service.mtgtop8_scraper import SCRAPER_NAME as MTGTOP8_SCRAPER_NAME
from analytics_service.mtgtop8_scraper import run_scrape as run_mtgtop8_scrape
from analytics_service.schemas import (
    ScraperConfigListResponse,
    ScraperConfigResponse,
    ScraperConfigUpdate,
)
from analytics_service.scryfall_sync import run_sync, should_sync
from analytics_service.settings import get_settings
from analytics_service.stats import router as stats_router
from common.cache import invalidate_user
from common.logging import configure_logging
from common.metrics import mount_metrics
from common.redis_client import get_redis

SERVICE_NAME = "analytics"
configure_logging(SERVICE_NAME)

_log = logging.getLogger("analytics.main")

_scheduler_task: asyncio.Task[None] | None = None
_mtgo_scheduler_task: asyncio.Task[None] | None = None
_mtgtop8_scheduler_task: asyncio.Task[None] | None = None
_cache_invalidator_task: asyncio.Task[None] | None = None


def reset_scheduler() -> None:
    """Test hook."""
    global _scheduler_task, _mtgo_scheduler_task, _mtgtop8_scheduler_task, _cache_invalidator_task
    _scheduler_task = None
    _mtgo_scheduler_task = None
    _mtgtop8_scheduler_task = None
    _cache_invalidator_task = None


async def _scheduler_loop() -> None:
    """Sleep-and-check loop driving periodic Scryfall syncs.

    Wakes up on the configured interval and asks ``should_sync`` —
    runs only when the cadence threshold has elapsed, so a manual
    admin sync resets the clock and we don't double-sync immediately
    after.
    """
    settings = get_settings()
    interval_seconds = settings.scryfall_sync_interval_days * 24 * 60 * 60
    sm = get_sessionmaker()
    while True:
        try:
            async with sm() as session:
                due = await should_sync(session)
            if due:
                await run_sync(sm)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never let scheduler crash kill the service
            _log.exception("scryfall scheduler iteration failed")
        await asyncio.sleep(interval_seconds)


async def _start_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task is not None:
        return
    _scheduler_task = asyncio.create_task(_scheduler_loop(), name="scryfall-scheduler")
    _log.info("scryfall scheduler task started")


async def _stop_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task is None:
        return
    _scheduler_task.cancel()
    try:
        await _scheduler_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 — surface but don't crash shutdown
        _log.exception("scryfall scheduler raised on shutdown")
    _scheduler_task = None


async def _read_scraper_config(
    sm: async_sessionmaker[AsyncSession],
    scraper_name: str,
) -> tuple[bool, int]:
    """Read enabled/interval_hours from ``analytics.scraper_config``.

    Falls back to env-based settings if the config row doesn't exist yet
    (pre-migration scenario).
    """
    try:
        async with sm() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT enabled, interval_hours "
                        "FROM analytics.scraper_config "
                        "WHERE scraper_name = :name"
                    ),
                    {"name": scraper_name},
                )
            ).one_or_none()
        if row is not None:
            return bool(row[0]), int(row[1])
    except Exception:  # noqa: BLE001 — table may not exist yet
        _log.debug("scraper_config read failed for %s; using env defaults", scraper_name)
    settings = get_settings()
    if scraper_name == MTGO_SCRAPER_NAME:
        return True, settings.mtgo_scrape_interval_hours
    return True, settings.mtgtop8_scrape_interval_hours


async def _mtgo_scheduler_loop() -> None:
    """Sleep-and-check loop for the MTGO results scraper.

    Reads ``analytics.scraper_config`` on each iteration to honour
    runtime enable/disable and interval changes. Falls back to
    env-based settings when the config table doesn't exist yet.
    """
    sm = get_sessionmaker()
    while True:
        try:
            enabled, interval_hours = await _read_scraper_config(sm, MTGO_SCRAPER_NAME)
            if enabled:
                async with sm() as session:
                    health = await get_scraper_health_row(session, MTGO_SCRAPER_NAME)
                if _mtgo_scrape_due(health, interval_hours):
                    await run_mtgo_scrape(sm)
            else:
                _log.debug("mtgo scraper disabled via config; skipping cycle")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never let scheduler crash kill the service
            _log.exception("mtgo scheduler iteration failed")
            interval_hours = get_settings().mtgo_scrape_interval_hours
        await asyncio.sleep(interval_hours * 60 * 60)


def _mtgo_scrape_due(health: dict[str, Any], interval_hours: int) -> bool:
    last = health.get("last_run_at")
    if last is None:
        return True
    now = datetime.now(UTC)
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (now - last) >= timedelta(hours=interval_hours)


async def _start_mtgo_scheduler() -> None:
    global _mtgo_scheduler_task
    if _mtgo_scheduler_task is not None:
        return
    _mtgo_scheduler_task = asyncio.create_task(_mtgo_scheduler_loop(), name="mtgo-scheduler")
    _log.info("mtgo scheduler task started")


async def _stop_mtgo_scheduler() -> None:
    global _mtgo_scheduler_task
    if _mtgo_scheduler_task is None:
        return
    _mtgo_scheduler_task.cancel()
    try:
        await _mtgo_scheduler_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 — surface but don't crash shutdown
        _log.exception("mtgo scheduler raised on shutdown")
    _mtgo_scheduler_task = None


# ---------------------------------------------------------------------------
# mtgtop8 scheduler
# ---------------------------------------------------------------------------


async def _mtgtop8_scheduler_loop() -> None:
    """Sleep-and-check loop for the mtgtop8 results scraper.

    Config-aware: reads ``analytics.scraper_config`` each iteration.
    """
    sm = get_sessionmaker()
    while True:
        try:
            enabled, interval_hours = await _read_scraper_config(sm, MTGTOP8_SCRAPER_NAME)
            if enabled:
                async with sm() as session:
                    health = await get_scraper_health_row(session, MTGTOP8_SCRAPER_NAME)
                if _mtgo_scrape_due(health, interval_hours):
                    await run_mtgtop8_scrape(sm)
            else:
                _log.debug("mtgtop8 scraper disabled via config; skipping cycle")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never let scheduler crash kill the service
            _log.exception("mtgtop8 scheduler iteration failed")
            interval_hours = get_settings().mtgtop8_scrape_interval_hours
        await asyncio.sleep(interval_hours * 60 * 60)


async def _start_mtgtop8_scheduler() -> None:
    global _mtgtop8_scheduler_task
    if _mtgtop8_scheduler_task is not None:
        return
    _mtgtop8_scheduler_task = asyncio.create_task(
        _mtgtop8_scheduler_loop(), name="mtgtop8-scheduler"
    )
    _log.info("mtgtop8 scheduler task started")


async def _stop_mtgtop8_scheduler() -> None:
    global _mtgtop8_scheduler_task
    if _mtgtop8_scheduler_task is None:
        return
    _mtgtop8_scheduler_task.cancel()
    try:
        await _mtgtop8_scheduler_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 — surface but don't crash shutdown
        _log.exception("mtgtop8 scheduler raised on shutdown")
    _mtgtop8_scheduler_task = None


# ---------------------------------------------------------------------------
# Cache invalidation
# ---------------------------------------------------------------------------


async def _cache_invalidation_loop() -> None:
    """Subscribe to ``match.parsed`` Redis pub/sub and invalidate cached
    stats for the affected user. Runs for the lifetime of the service."""
    settings = get_settings()
    try:
        redis_client = await get_redis(settings.redis_url)
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("match.parsed")
        _log.info("cache invalidator subscribed to match.parsed")
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                import json as _json

                payload = _json.loads(message["data"])
                user_id = payload.get("user_id")
                if user_id is not None:
                    deleted = await invalidate_user(redis_client, int(user_id))
                    if deleted:
                        _log.debug("invalidated %d cache keys for user_id=%s", deleted, user_id)
            except Exception:  # noqa: BLE001
                _log.warning("cache invalidation message handling failed", exc_info=True)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        _log.exception("cache invalidation loop failed")


async def _start_cache_invalidator() -> None:
    global _cache_invalidator_task
    if _cache_invalidator_task is not None:
        return
    _cache_invalidator_task = asyncio.create_task(
        _cache_invalidation_loop(), name="cache-invalidator"
    )
    _log.info("cache invalidator task started")


async def _stop_cache_invalidator() -> None:
    global _cache_invalidator_task
    if _cache_invalidator_task is None:
        return
    _cache_invalidator_task.cancel()
    try:
        await _cache_invalidator_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001
        _log.exception("cache invalidator raised on shutdown")
    _cache_invalidator_task = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        await _start_scheduler()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start scryfall scheduler; healthz remains available")
    try:
        await _start_mtgo_scheduler()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start mtgo scheduler; healthz remains available")
    try:
        await _start_mtgtop8_scheduler()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start mtgtop8 scheduler; healthz remains available")
    try:
        await _start_cache_invalidator()
    except Exception:  # noqa: BLE001 — cache is optional; service works without it
        _log.exception("failed to start cache invalidator; service continues without caching")
    try:
        yield
    finally:
        await _stop_cache_invalidator()
        await _stop_mtgtop8_scheduler()
        await _stop_mtgo_scheduler()
        await _stop_scheduler()


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)
mount_metrics(app, SERVICE_NAME)
app.include_router(archetypes_router)
app.include_router(stats_router)
app.include_router(game_stats_router)
app.include_router(card_stats_router)
app.include_router(cards_router)
app.include_router(matches_router)
app.include_router(metagame_router)


admin_router = APIRouter(prefix="/analytics/admin", tags=["admin"])


@admin_router.post("/sync-cards", status_code=202)
async def sync_cards(
    background_tasks: BackgroundTasks,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, str]:
    """Trigger a Scryfall card sync.

    Runs in the background — the bulk-data download + parse + upsert
    takes minutes; tying up an admin request that long is the wrong
    shape. Returns 202 immediately; progress shows up in service logs.
    """
    background_tasks.add_task(run_sync, get_sessionmaker())
    return {"status": "sync_started"}


@admin_router.post("/scrape-mtgo", status_code=202)
async def scrape_mtgo(
    background_tasks: BackgroundTasks,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, str]:
    """Trigger an MTGO results scrape in the background."""
    background_tasks.add_task(run_mtgo_scrape, get_sessionmaker())
    return {"status": "scrape_started"}


@admin_router.post("/scrape-mtgtop8", status_code=202)
async def scrape_mtgtop8(
    background_tasks: BackgroundTasks,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, str]:
    """Trigger an mtgtop8.com results scrape in the background."""
    background_tasks.add_task(run_mtgtop8_scrape, get_sessionmaker())
    return {"status": "scrape_started"}


@admin_router.post("/scraper-health/reset")
async def scraper_health_reset(
    scraper_name: Annotated[str, Query()],
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, Any]:
    """Reset a scraper's consecutive_failures and is_broken flag.

    Useful after deploying a fix for a BROKEN scraper so it re-enters
    the normal schedule without waiting for a successful run.
    """
    allowed = {MTGO_SCRAPER_NAME, MTGTOP8_SCRAPER_NAME}
    if scraper_name not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"unknown scraper_name; allowed: {sorted(allowed)}"},
        )
    sm = get_sessionmaker()
    async with sm() as session:
        return await reset_scraper_health_row(session, scraper_name)


@admin_router.get("/scraper-health")
async def scraper_health(
    _admin: AuthenticatedUser = Depends(require_admin),
    scraper_name: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Return scraper health.

    Without ``scraper_name``: returns ``{"scrapers": [...]}``, one entry
    per registered scraper. With ``scraper_name``: returns that single
    scraper's health dict (backward-compatible with the pre-v0.9.4 shape).
    """
    sm = get_sessionmaker()
    if scraper_name is not None:
        async with sm() as session:
            return await get_scraper_health_row(session, scraper_name)
    async with sm() as session:
        mtgo = await get_scraper_health_row(session, MTGO_SCRAPER_NAME)
        mtgtop8 = await get_scraper_health_row(session, MTGTOP8_SCRAPER_NAME)
    return {"scrapers": [mtgo, mtgtop8]}


@admin_router.get("/cards-status")
async def cards_status(
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, Any]:
    """Card-mirror summary for the admin dashboard.

    ``last_sync_at`` is ``MAX(synced_at)`` over the table rather than a
    dedicated bookkeeping row — the upsert path stamps every row on
    each refresh, so the column already tracks the freshest sync.
    """
    sm = get_sessionmaker()
    async with sm() as session:
        count_row = await session.execute(text("SELECT COUNT(*) FROM catalog.cards"))
        last_row = await session.execute(text("SELECT MAX(synced_at) FROM catalog.cards"))
        card_count = int(count_row.scalar_one())
        last_sync_at: datetime | None = last_row.scalar_one_or_none()
    return {
        "card_count": card_count,
        "last_sync_at": last_sync_at.isoformat() if last_sync_at is not None else None,
    }


# ---------------------------------------------------------------------------
# Admin matches — system-wide match listing (ROADMAP #11)
# ---------------------------------------------------------------------------

_ADMIN_MATCHES_DEFAULT_PER_PAGE = 20
_ADMIN_MATCHES_MAX_PER_PAGE = 100


class AdminMatchItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    match_id: str
    user_id: int
    user_email: str | None = None
    format_: str | None = Field(default=None, alias="format")
    players: list[str] = Field(default_factory=list)
    match_result: str | None = None
    winner: str | None = None
    game_count: int = 0
    played_at: datetime | None = None


class AdminMatchListResponse(BaseModel):
    matches: list[AdminMatchItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = _ADMIN_MATCHES_DEFAULT_PER_PAGE


@admin_router.get("/matches", response_model=AdminMatchListResponse)
async def admin_list_matches(
    _admin: AuthenticatedUser = Depends(require_admin),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_MATCHES_MAX_PER_PAGE)
    ] = _ADMIN_MATCHES_DEFAULT_PER_PAGE,
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    result: Annotated[str | None, Query()] = None,
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
) -> AdminMatchListResponse:
    """System-wide match listing for admins — all users' matches."""
    sm = get_sessionmaker()
    async with sm() as session:
        # Build WHERE clauses dynamically
        conditions: list[str] = []
        params: dict[str, Any] = {}
        if format and format.lower() != "all":
            conditions.append("LOWER(m.format) = :format")
            params["format"] = format.lower()
        if date_from:
            conditions.append("COALESCE(m.played_at, m.parsed_at) >= :date_from")
            params["date_from"] = datetime.combine(date_from, datetime.min.time())
        if date_to:
            conditions.append("COALESCE(m.played_at, m.parsed_at) < :date_to")
            params["date_to"] = datetime.combine(date_to + timedelta(days=1), datetime.min.time())
        if opponent:
            conditions.append("m.players::text ILIKE :opponent")
            params["opponent"] = f"%{opponent}%"

        where_clause = (" AND " + " AND ".join(conditions)) if conditions else ""

        # Count total
        count_sql = text(f"SELECT COUNT(*) FROM parser.matches m WHERE 1=1{where_clause}")
        total = int((await session.execute(count_sql, params)).scalar_one())

        # Fetch page with user email join
        offset = (page - 1) * per_page
        fetch_sql = text(
            f"""
            SELECT m.id, m.user_id, u.email, m.format, m.players,
                   m.match_result, m.winner, m.game_count,
                   COALESCE(m.played_at, m.parsed_at) AS played_at
            FROM parser.matches m
            LEFT JOIN auth.users u ON u.id = m.user_id
            WHERE 1=1{where_clause}
            ORDER BY COALESCE(m.played_at, m.parsed_at) DESC
            LIMIT :limit OFFSET :offset
            """
        )
        params["limit"] = per_page
        params["offset"] = offset
        rows = (await session.execute(fetch_sql, params)).all()

    # Post-filter by result if requested (W/L/D classification needs
    # game-winner counts which are expensive to do in SQL; since we're
    # paginated and the filter is rare, we accept slightly imprecise
    # total counts when a result filter is active).
    # For the result filter, classify using match_result string.
    items: list[AdminMatchItem] = []
    for row in rows:
        (
            match_id,
            user_id,
            email,
            fmt,
            players,
            match_result,
            winner,
            game_count,
            played_at,
        ) = row
        item = AdminMatchItem(
            match_id=str(match_id),
            user_id=int(user_id),
            user_email=email,
            format=fmt,
            players=[str(p) for p in (players or [])],
            match_result=match_result,
            winner=winner,
            game_count=int(game_count) if game_count else 0,
            played_at=played_at,
        )
        items.append(item)

    # Result filtering on the fetched page
    if result and result.lower() != "all":
        result_key = result.lower()
        filtered: list[AdminMatchItem] = []
        for item in items:
            if result_key in ("w", "wins") and item.winner and item.players:
                if item.winner == (item.players[0] if item.players else ""):
                    filtered.append(item)
            elif result_key in ("l", "losses") and item.winner and item.players:
                if item.winner != (item.players[0] if item.players else ""):
                    filtered.append(item)
            elif result_key in ("d", "draws") and not item.winner and item.game_count > 0:
                filtered.append(item)
        items = filtered

    return AdminMatchListResponse(matches=items, total=total, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# Scraper config admin API (F12)
# ---------------------------------------------------------------------------

_KNOWN_SCRAPERS = {MTGO_SCRAPER_NAME, MTGTOP8_SCRAPER_NAME}
_SCRAPER_EVENTS_DEFAULT_PER_PAGE = 20
_SCRAPER_EVENTS_MAX_PER_PAGE = 100


@admin_router.get("/scrapers", response_model=ScraperConfigListResponse)
async def list_scrapers(
    _admin: AuthenticatedUser = Depends(require_admin),
) -> ScraperConfigListResponse:
    """List all scrapers with merged config + health data."""
    sm = get_sessionmaker()
    scrapers: list[ScraperConfigResponse] = []
    async with sm() as session:
        for name in sorted(_KNOWN_SCRAPERS):
            config_row = (
                await session.execute(
                    text(
                        "SELECT enabled, interval_hours "
                        "FROM analytics.scraper_config "
                        "WHERE scraper_name = :name"
                    ),
                    {"name": name},
                )
            ).one_or_none()
            health = await get_scraper_health_row(session, name)
            scrapers.append(
                ScraperConfigResponse(
                    scraper_name=name,
                    enabled=bool(config_row[0]) if config_row else True,
                    interval_hours=int(config_row[1]) if config_row else 24,
                    last_run_at=health.get("last_run_at"),
                    last_success_at=health.get("last_success_at"),
                    consecutive_failures=health.get("consecutive_failures", 0),
                    is_broken=health.get("is_broken", False),
                    last_error=health.get("last_error"),
                )
            )
    return ScraperConfigListResponse(scrapers=scrapers)


@admin_router.patch("/scrapers/{name}", response_model=ScraperConfigResponse)
async def update_scraper_config(
    name: str,
    body: ScraperConfigUpdate,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> ScraperConfigResponse:
    """Update enabled/interval for a scraper."""
    if name not in _KNOWN_SCRAPERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"unknown scraper; allowed: {sorted(_KNOWN_SCRAPERS)}"},
        )
    if body.enabled is None and body.interval_hours is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "nothing to update; provide enabled and/or interval_hours"},
        )
    sm = get_sessionmaker()
    async with sm() as session:
        # Upsert the config row.
        sets: list[str] = []
        params: dict[str, Any] = {"name": name}
        if body.enabled is not None:
            sets.append("enabled = :enabled")
            params["enabled"] = body.enabled
        if body.interval_hours is not None:
            sets.append("interval_hours = :interval_hours")
            params["interval_hours"] = body.interval_hours
        set_clause = ", ".join(sets)
        await session.execute(
            text(
                f"INSERT INTO analytics.scraper_config (scraper_name, enabled, interval_hours) "
                f"VALUES (:name, COALESCE(:enabled_val, TRUE), COALESCE(:interval_val, 24)) "
                f"ON CONFLICT (scraper_name) DO UPDATE SET {set_clause}"
            ),
            {
                **params,
                "enabled_val": body.enabled,
                "interval_val": body.interval_hours,
            },
        )
        await session.commit()
        # Read back merged state.
        config_row = (
            await session.execute(
                text(
                    "SELECT enabled, interval_hours "
                    "FROM analytics.scraper_config "
                    "WHERE scraper_name = :name"
                ),
                {"name": name},
            )
        ).one()
        health = await get_scraper_health_row(session, name)
    return ScraperConfigResponse(
        scraper_name=name,
        enabled=bool(config_row[0]),
        interval_hours=int(config_row[1]),
        last_run_at=health.get("last_run_at"),
        last_success_at=health.get("last_success_at"),
        consecutive_failures=health.get("consecutive_failures", 0),
        is_broken=health.get("is_broken", False),
        last_error=health.get("last_error"),
    )


@admin_router.get("/scrapers/{name}/events")
async def scraper_events(
    name: str,
    _admin: AuthenticatedUser = Depends(require_admin),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_SCRAPER_EVENTS_MAX_PER_PAGE)
    ] = _SCRAPER_EVENTS_DEFAULT_PER_PAGE,
) -> dict[str, Any]:
    """Paginated events for a specific scraper."""
    if name not in _KNOWN_SCRAPERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"unknown scraper; allowed: {sorted(_KNOWN_SCRAPERS)}"},
        )
    offset = (page - 1) * per_page
    sm = get_sessionmaker()
    table = "analytics.mtgtop8_events" if name == "mtgtop8" else "analytics.mtgo_events"
    async with sm() as session:
        total = int(
            (await session.execute(text(f"SELECT COUNT(*) FROM {table}"))).scalar_one()
        )
        if name == "mtgtop8":
            rows = (
                await session.execute(
                    text(
                        f"SELECT id, event_name, format, event_date, player_count, scraped_at "
                        f"FROM {table} ORDER BY event_date DESC NULLS LAST "
                        f"LIMIT :limit OFFSET :offset"
                    ),
                    {"limit": per_page, "offset": offset},
                )
            ).all()
            events = [
                {
                    "event_id": int(r[0]),
                    "event_name": r[1],
                    "format": r[2],
                    "event_date": r[3].isoformat() if r[3] else None,
                    "player_count": int(r[4]) if r[4] is not None else None,
                    "scraped_at": r[5].isoformat() if r[5] else None,
                }
                for r in rows
            ]
        else:
            rows = (
                await session.execute(
                    text(
                        f"SELECT id, event_name, format, event_date, scraped_at "
                        f"FROM {table} ORDER BY event_date DESC NULLS LAST "
                        f"LIMIT :limit OFFSET :offset"
                    ),
                    {"limit": per_page, "offset": offset},
                )
            ).all()
            events = [
                {
                    "event_id": int(r[0]),
                    "event_name": r[1],
                    "format": r[2],
                    "event_date": r[3].isoformat() if r[3] else None,
                    "player_count": None,
                    "scraped_at": r[4].isoformat() if r[4] else None,
                }
                for r in rows
            ]
    return {"events": events, "total": total, "page": page, "per_page": per_page}


@admin_router.get("/scrapers/{name}/events/{event_id}")
async def scraper_event_detail(
    name: str,
    event_id: int,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> dict[str, Any]:
    """Single event with all results for a specific scraper."""
    if name not in _KNOWN_SCRAPERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"unknown scraper; allowed: {sorted(_KNOWN_SCRAPERS)}"},
        )
    sm = get_sessionmaker()
    async with sm() as session:
        if name == "mtgtop8":
            event_row = (
                await session.execute(
                    text(
                        "SELECT id, event_name, format, event_date, player_count, event_url "
                        "FROM analytics.mtgtop8_events WHERE id = :id"
                    ),
                    {"id": event_id},
                )
            ).one_or_none()
            if event_row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={"error": "event_not_found"},
                )
            result_rows = (
                await session.execute(
                    text(
                        "SELECT player_name, placement, deck_name, "
                        "decklist_main, decklist_sideboard "
                        "FROM analytics.mtgtop8_results "
                        "WHERE event_id = :eid "
                        "ORDER BY placement NULLS LAST, player_name"
                    ),
                    {"eid": event_id},
                )
            ).all()
            return {
                "event_id": int(event_row[0]),
                "event_name": event_row[1],
                "format": event_row[2],
                "event_date": event_row[3].isoformat() if event_row[3] else None,
                "player_count": int(event_row[4]) if event_row[4] is not None else None,
                "event_url": event_row[5],
                "source": "mtgtop8",
                "results": [
                    {
                        "player_name": r[0],
                        "placement": int(r[1]) if r[1] is not None else None,
                        "deck_name": r[2],
                        "decklist_main": r[3],
                        "decklist_sideboard": r[4],
                    }
                    for r in result_rows
                ],
            }
        else:
            event_row = (
                await session.execute(
                    text(
                        "SELECT id, event_name, format, event_date, event_url "
                        "FROM analytics.mtgo_events WHERE id = :id"
                    ),
                    {"id": event_id},
                )
            ).one_or_none()
            if event_row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={"error": "event_not_found"},
                )
            result_rows = (
                await session.execute(
                    text(
                        "SELECT player_name, placement, "
                        "decklist_main, decklist_sideboard "
                        "FROM analytics.mtgo_results "
                        "WHERE event_id = :eid "
                        "ORDER BY placement NULLS LAST, player_name"
                    ),
                    {"eid": event_id},
                )
            ).all()
            return {
                "event_id": int(event_row[0]),
                "event_name": event_row[1],
                "format": event_row[2],
                "event_date": event_row[3].isoformat() if event_row[3] else None,
                "player_count": None,
                "event_url": event_row[4],
                "source": "mtgo",
                "results": [
                    {
                        "player_name": r[0],
                        "placement": int(r[1]) if r[1] is not None else None,
                        "deck_name": None,
                        "decklist_main": r[2],
                        "decklist_sideboard": r[3],
                    }
                    for r in result_rows
                ],
            }


app.include_router(admin_router)


@app.get("/healthz")
@app.get("/analytics/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
