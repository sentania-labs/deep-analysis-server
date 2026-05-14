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

from analytics_service.archetypes import router as archetypes_router
from analytics_service.card_stats import router as card_stats_router
from analytics_service.cards import router as cards_router
from analytics_service.db import get_sessionmaker
from analytics_service.deps import AuthenticatedUser, require_admin
from analytics_service.game_stats import router as game_stats_router
from analytics_service.matches import router as matches_router
from analytics_service.mtgo_scraper import SCRAPER_NAME as MTGO_SCRAPER_NAME
from analytics_service.mtgo_scraper import get_health as get_scraper_health_row
from analytics_service.mtgo_scraper import reset_health as reset_scraper_health_row
from analytics_service.mtgo_scraper import run_scrape as run_mtgo_scrape
from analytics_service.mtgtop8_scraper import SCRAPER_NAME as MTGTOP8_SCRAPER_NAME
from analytics_service.mtgtop8_scraper import run_scrape as run_mtgtop8_scrape
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


async def _mtgo_scheduler_loop() -> None:
    """Sleep-and-check loop for the MTGO results scraper.

    On the first iteration, asks ``scraper_health`` whether the last
    run is older than the configured interval (or has never happened);
    if so, runs immediately. Then sleeps the configured interval and
    repeats. ``run_mtgo_scrape`` itself never raises, so this loop only
    has to guard against unexpected DB errors when reading health.
    """
    settings = get_settings()
    interval_seconds = settings.mtgo_scrape_interval_hours * 60 * 60
    sm = get_sessionmaker()
    while True:
        try:
            async with sm() as session:
                health = await get_scraper_health_row(session, MTGO_SCRAPER_NAME)
            if _mtgo_scrape_due(health, settings.mtgo_scrape_interval_hours):
                await run_mtgo_scrape(sm)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never let scheduler crash kill the service
            _log.exception("mtgo scheduler iteration failed")
        await asyncio.sleep(interval_seconds)


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
    """Sleep-and-check loop for the mtgtop8 results scraper."""
    settings = get_settings()
    interval_seconds = settings.mtgtop8_scrape_interval_hours * 60 * 60
    sm = get_sessionmaker()
    while True:
        try:
            async with sm() as session:
                health = await get_scraper_health_row(session, MTGTOP8_SCRAPER_NAME)
            if _mtgo_scrape_due(health, settings.mtgtop8_scrape_interval_hours):
                await run_mtgtop8_scrape(sm)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never let scheduler crash kill the service
            _log.exception("mtgtop8 scheduler iteration failed")
        await asyncio.sleep(interval_seconds)


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


app.include_router(admin_router)


@app.get("/healthz")
@app.get("/analytics/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
