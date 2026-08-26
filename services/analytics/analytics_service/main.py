from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from analytics_service.archetypes import router as archetypes_router
from analytics_service.bnr_events import router as bnr_events_router
from analytics_service.card_materializer import card_materializer_loop, card_stats_backfill_loop
from analytics_service.card_stats import router as card_stats_router
from analytics_service.cards import router as cards_router
from analytics_service.db import get_session, get_sessionmaker
from analytics_service.deps import AuthenticatedUser, require_admin
from analytics_service.game_stats import router as game_stats_router
from analytics_service.matches import router as matches_router
from analytics_service.metagame import router as metagame_router
from analytics_service.ml_classifier import get_status as ml_get_status
from analytics_service.ml_classifier import load_model as ml_load_model
from analytics_service.ml_classifier import retrain as ml_retrain
from analytics_service.models import ArchetypeLabelMapping, CanonicalArchetype
from analytics_service.mtgo_scraper import SCRAPER_NAME as MTGO_SCRAPER_NAME
from analytics_service.mtgo_scraper import get_health as get_scraper_health_row
from analytics_service.mtgo_scraper import reset_health as reset_scraper_health_row
from analytics_service.mtgo_scraper import run_scrape as run_mtgo_scrape
from analytics_service.mtgtop8_scraper import SCRAPER_NAME as MTGTOP8_SCRAPER_NAME
from analytics_service.mtgtop8_scraper import run_scrape as run_mtgtop8_scrape
from analytics_service.schemas import (
    AdminMatchItem,
    AdminMatchListResponse,
    ArchetypeLabelMappingCreate,
    ArchetypeLabelMappingListView,
    ArchetypeLabelMappingRecord,
    CanonicalArchetypeCreate,
    CanonicalArchetypeListView,
    CanonicalArchetypeRecord,
    ClassifierStatus,
    MatchReviewRequest,
    ScraperConfigListResponse,
    ScraperConfigResponse,
    ScraperConfigUpdate,
    TrainResult,
)
from analytics_service.scraper_lock import (
    TRIGGER_MANUAL,
    TRIGGER_SCHEDULED,
    ScrapeAlreadyRunning,
    ScrapeLeaseLost,
    ScraperRun,
)
from analytics_service.scraper_lock import acquire as acquire_scraper_lock
from analytics_service.scraper_lock import get_run as get_scraper_run
from analytics_service.scraper_lock import run_locked as run_scrape_locked
from analytics_service.scraper_lock import run_status_fields as scraper_run_status_fields
from analytics_service.scryfall_sync import run_sync, should_sync
from analytics_service.settings import get_settings
from analytics_service.stats import router as stats_router
from common.background_loop import BackgroundLoop
from common.cache import invalidate_user
from common.logging import configure_logging
from common.metrics import start_metrics_server
from common.redis_client import get_redis

SERVICE_NAME = "analytics"
configure_logging(SERVICE_NAME)

_log = logging.getLogger("analytics.main")

# Indirection for asyncio.sleep so tests can patch backoff delays
# without interfering with the global event loop.
_async_sleep = asyncio.sleep

_cache_invalidator_task: asyncio.Task[None] | None = None
_card_materializer_task: asyncio.Task[None] | None = None
_card_backfill_task: asyncio.Task[None] | None = None


# ---------------------------------------------------------------------------
# Scryfall scheduler — BackgroundLoop
# ---------------------------------------------------------------------------


async def _scryfall_tick() -> None:
    """Single iteration: sync if cadence threshold has elapsed."""
    sm = get_sessionmaker()
    async with sm() as session:
        due = await should_sync(session)
    if due:
        await run_sync(sm)


async def _scryfall_interval() -> float:
    settings = get_settings()
    return float(settings.scryfall_sync_interval_days * 24 * 60 * 60)


_scryfall_loop = BackgroundLoop("scryfall-scheduler", _scryfall_tick, _scryfall_interval)


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


_ScrapeRunner = Callable[[async_sessionmaker[AsyncSession]], Awaitable[Any]]


async def _run_scrape_if_idle(
    scraper_name: str,
    runner: _ScrapeRunner,
    sm: async_sessionmaker[AsyncSession],
) -> None:
    """Scheduler path: run the scrape unless a run already holds the lock.

    A skipped cycle is normal, not an error: an admin kicked off a
    manual run (or another replica got there first) and duplicating the
    fetch would only double the load on the upstream site.
    """
    try:
        await run_scrape_locked(
            scraper_name,
            lambda: runner(sm),
            trigger=TRIGGER_SCHEDULED,
        )
    except ScrapeLeaseLost:
        _log.warning(
            "scheduled scrape aborted; lock lease was lost mid-run",
            extra={"scraper_name": scraper_name},
        )
    except ScrapeAlreadyRunning as exc:
        _log.info(
            "scheduled scrape skipped; run already in progress",
            extra={
                "scraper_name": scraper_name,
                "running_since": exc.run.started_at.isoformat() if exc.run else None,
                "run_trigger": exc.run.trigger if exc.run else None,
            },
        )


async def _run_scrape_holding(
    scraper_name: str,
    runner: _ScrapeRunner,
    sm: async_sessionmaker[AsyncSession],
    run: ScraperRun,
) -> None:
    """Background-task path: the lock was acquired by the HTTP handler."""
    try:
        await run_scrape_locked(
            scraper_name,
            lambda: runner(sm),
            trigger=run.trigger,
            run=run,
        )
    except ScrapeLeaseLost:
        # The run was cut short because another owner took the lock. The
        # 202 is already out the door, so this is the only place it can
        # be reported.
        _log.warning(
            "manual scrape aborted; lock lease was lost mid-run",
            extra={"scraper_name": scraper_name, "run_id": run.run_id},
        )


def _already_running_response(exc: ScrapeAlreadyRunning) -> JSONResponse:
    """409 body for a duplicate trigger. Machine-readable on purpose."""
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "error": "scrape_already_running",
            "scraper_name": exc.job_name,
            "running_since": exc.run.started_at.isoformat() if exc.run else None,
            "run_trigger": exc.run.trigger if exc.run else None,
        },
    )


_mtgo_interval_hours: int = 24  # updated each tick from scraper_config


async def _mtgo_tick() -> None:
    """Single iteration for the MTGO results scraper."""
    global _mtgo_interval_hours
    sm = get_sessionmaker()
    enabled, interval_hours = await _read_scraper_config(sm, MTGO_SCRAPER_NAME)
    _mtgo_interval_hours = interval_hours
    if enabled:
        async with sm() as session:
            health = await get_scraper_health_row(session, MTGO_SCRAPER_NAME)
        if _mtgo_scrape_due(health, interval_hours):
            await _run_scrape_if_idle(MTGO_SCRAPER_NAME, run_mtgo_scrape, sm)
    else:
        _log.debug("mtgo scraper disabled via config; skipping cycle")


def _mtgo_scrape_due(health: dict[str, Any], interval_hours: int) -> bool:
    last = health.get("last_run_at")
    if last is None:
        return True
    now = datetime.now(UTC)
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (now - last) >= timedelta(hours=interval_hours)


async def _mtgo_interval() -> float:
    return float(_mtgo_interval_hours * 60 * 60)


_mtgo_loop = BackgroundLoop("mtgo-scheduler", _mtgo_tick, _mtgo_interval)


# ---------------------------------------------------------------------------
# mtgtop8 scheduler — BackgroundLoop
# ---------------------------------------------------------------------------

_mtgtop8_interval_hours: int = 24  # updated each tick from scraper_config


async def _mtgtop8_tick() -> None:
    """Single iteration for the mtgtop8 results scraper."""
    global _mtgtop8_interval_hours
    sm = get_sessionmaker()
    enabled, interval_hours = await _read_scraper_config(sm, MTGTOP8_SCRAPER_NAME)
    _mtgtop8_interval_hours = interval_hours
    if enabled:
        async with sm() as session:
            health = await get_scraper_health_row(session, MTGTOP8_SCRAPER_NAME)
        if _mtgo_scrape_due(health, interval_hours):
            await _run_scrape_if_idle(MTGTOP8_SCRAPER_NAME, run_mtgtop8_scrape, sm)
    else:
        _log.debug("mtgtop8 scraper disabled via config; skipping cycle")


async def _mtgtop8_interval() -> float:
    return float(_mtgtop8_interval_hours * 60 * 60)


_mtgtop8_loop = BackgroundLoop("mtgtop8-scheduler", _mtgtop8_tick, _mtgtop8_interval)


def reset_scheduler() -> None:
    """Test hook."""
    global _cache_invalidator_task, _card_materializer_task
    _scryfall_loop.reset()
    _mtgo_loop.reset()
    _mtgtop8_loop.reset()
    _cache_invalidator_task = None
    _card_materializer_task = None


# ---------------------------------------------------------------------------
# Cache invalidation
# ---------------------------------------------------------------------------


async def _cache_invalidation_loop() -> None:
    """Subscribe to ``match.parsed`` Redis pub/sub and invalidate cached
    stats for the affected user. Runs for the lifetime of the service.

    Wraps the subscription in a retry loop with exponential backoff so
    that a transient Redis disconnect does not permanently kill cache
    invalidation (the previous behaviour). On reconnect the backoff
    resets and the loop resumes normally.
    """
    settings = get_settings()
    backoff = 1.0
    max_backoff = 60.0
    while True:
        try:
            redis_client = await get_redis(settings.redis_url)
            pubsub = redis_client.pubsub()
            await pubsub.subscribe("match.parsed")
            _log.info("cache invalidator subscribed to match.parsed")
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                backoff = 1.0  # reset once we receive a real data message
                try:
                    payload = json.loads(message["data"])
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
            _log.warning(
                "cache invalidation loop lost Redis connection; retrying in %.0fs",
                backoff,
                exc_info=True,
            )
            await _async_sleep(backoff)
            backoff = min(backoff * 2, max_backoff)


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


# ---------------------------------------------------------------------------
# Card game stats materializer
# ---------------------------------------------------------------------------


async def _start_card_materializer() -> None:
    global _card_materializer_task
    if _card_materializer_task is not None:
        return
    settings = get_settings()
    sm = get_sessionmaker()
    _card_materializer_task = asyncio.create_task(
        card_materializer_loop(settings.redis_url, sm),
        name="card-materializer",
    )
    _log.info("card materializer task started")


async def _stop_card_materializer() -> None:
    global _card_materializer_task
    if _card_materializer_task is None:
        return
    _card_materializer_task.cancel()
    try:
        await _card_materializer_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001
        _log.exception("card materializer raised on shutdown")
    _card_materializer_task = None


async def _start_card_backfill() -> None:
    global _card_backfill_task
    if _card_backfill_task is not None:
        return
    sm = get_sessionmaker()
    _card_backfill_task = asyncio.create_task(
        card_stats_backfill_loop(sm),
        name="card-stats-backfill",
    )
    _log.info("card stats backfill task started")


async def _stop_card_backfill() -> None:
    global _card_backfill_task
    if _card_backfill_task is None:
        return
    _card_backfill_task.cancel()
    try:
        await _card_backfill_task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001
        _log.exception("card stats backfill raised on shutdown")
    _card_backfill_task = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    start_metrics_server(SERVICE_NAME, get_settings().metrics_port)
    try:
        await _scryfall_loop.start()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start scryfall scheduler; healthz remains available")
    try:
        await _mtgo_loop.start()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start mtgo scheduler; healthz remains available")
    try:
        await _mtgtop8_loop.start()
    except Exception:  # noqa: BLE001 — healthz still serves even if scheduler fails
        _log.exception("failed to start mtgtop8 scheduler; healthz remains available")
    try:
        await _start_cache_invalidator()
    except Exception:  # noqa: BLE001 — cache is optional; service works without it
        _log.exception("failed to start cache invalidator; service continues without caching")
    try:
        await _start_card_materializer()
    except Exception:  # noqa: BLE001 — materializer is best-effort
        _log.exception("failed to start card materializer; service continues without it")
    try:
        await _start_card_backfill()
    except Exception:  # noqa: BLE001 — backfill is best-effort
        _log.exception("failed to start card stats backfill; service continues without it")
    try:
        ml_load_model()
    except Exception:  # noqa: BLE001 — ML model is optional
        _log.info("ML classifier model not loaded at startup (not yet trained or unavailable)")
    try:
        yield
    finally:
        await _stop_card_backfill()
        await _stop_card_materializer()
        await _stop_cache_invalidator()
        await _mtgtop8_loop.stop()
        await _mtgo_loop.stop()
        await _scryfall_loop.stop()


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)
app.include_router(archetypes_router)
app.include_router(bnr_events_router)
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
) -> Any:
    """Trigger an MTGO results scrape in the background.

    The lock is taken here, before the 202, so a second click gets an
    honest 409 instead of silently starting a duplicate fetch.
    """
    try:
        run = await acquire_scraper_lock(MTGO_SCRAPER_NAME, trigger=TRIGGER_MANUAL)
    except ScrapeAlreadyRunning as exc:
        return _already_running_response(exc)
    background_tasks.add_task(
        _run_scrape_holding, MTGO_SCRAPER_NAME, run_mtgo_scrape, get_sessionmaker(), run
    )
    return {"status": "scrape_started", "run_id": run.run_id}


@admin_router.post("/scrape-mtgtop8", status_code=202)
async def scrape_mtgtop8(
    background_tasks: BackgroundTasks,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> Any:
    """Trigger an mtgtop8.com results scrape in the background."""
    try:
        run = await acquire_scraper_lock(MTGTOP8_SCRAPER_NAME, trigger=TRIGGER_MANUAL)
    except ScrapeAlreadyRunning as exc:
        return _already_running_response(exc)
    background_tasks.add_task(
        _run_scrape_holding, MTGTOP8_SCRAPER_NAME, run_mtgtop8_scrape, get_sessionmaker(), run
    )
    return {"status": "scrape_started", "run_id": run.run_id}


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


async def _with_run_status(health: dict[str, Any]) -> dict[str, Any]:
    """Merge live-run state into a scraper health dict."""
    name = str(health.get("scraper_name") or "")
    run = await get_scraper_run(name)
    return {**health, **scraper_run_status_fields(run)}


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
            health = await get_scraper_health_row(session, scraper_name)
        return await _with_run_status(health)
    async with sm() as session:
        mtgo = await get_scraper_health_row(session, MTGO_SCRAPER_NAME)
        mtgtop8 = await get_scraper_health_row(session, MTGTOP8_SCRAPER_NAME)
    return {
        "scrapers": [
            await _with_run_status(mtgo),
            await _with_run_status(mtgtop8),
        ]
    }


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


def _is_true_draw(wins_by_player: dict[str, int], *, match_tied: bool = False) -> bool:
    """A match is a true draw when either:

    1. At least two players have equal, nonzero game-win counts, OR
    2. The MTGO log explicitly reported "Match Tied" (``match_tied=True``).

    Case 2 covers intentional draws where both players have 0 game wins.
    Without the ``match_tied`` flag, those 0-0 matches would be
    indistinguishable from partial/unresolved parses.
    """
    if match_tied:
        return True
    if len(wins_by_player) < 2:
        return False
    distinct = set(wins_by_player.values())
    return len(distinct) == 1 and 0 not in distinct


_VALID_REVIEW_STATUS_FILTERS = {"all", "pending_review", "rejected", "normal"}


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
    review_status: Annotated[str | None, Query()] = None,
) -> AdminMatchListResponse:
    """System-wide match listing for admins — all users' matches.

    Unlike the user-facing list, this surfaces ``pending_review`` and
    ``'rejected'`` rows (the holding pen) so an admin can triage them.
    The ``review_status`` filter controls visibility:

    * ``None`` / ``'all'`` — every row, default.
    * ``'pending_review'`` — only inconclusive parses waiting on a
      verdict.
    * ``'rejected'`` — only admin-discarded rows.
    * ``'normal'`` — only ``review_status IS NULL`` (matches what
      regular users see).
    """
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

        rs_filter = (review_status or "").lower()
        if rs_filter and rs_filter not in _VALID_REVIEW_STATUS_FILTERS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "invalid_review_status",
                    "allowed": sorted(_VALID_REVIEW_STATUS_FILTERS),
                },
            )
        if rs_filter == "pending_review":
            conditions.append("m.review_status = 'pending_review'")
        elif rs_filter == "rejected":
            conditions.append("m.review_status = 'rejected'")
        elif rs_filter == "normal":
            conditions.append("m.review_status IS NULL")
        # rs_filter == "" or "all" leaves all rows visible.

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
                   COALESCE(m.played_at, m.parsed_at) AS played_at,
                   m.review_status,
                   m.review_reason,
                   m.match_tied
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

    # Compute per-match game-winner counts so we can mark *true* draws
    # (both players have equal nonzero game wins, or match_tied) — see issue #71.
    match_ids = [row[0] for row in rows]
    # Build a quick lookup of match_tied by match_id from the fetched rows.
    match_tied_by_id: dict[Any, bool] = {r[0]: bool(r[11]) for r in rows}
    draw_match_ids: set[Any] = set()
    if match_ids:
        async with sm() as session:
            game_win_rows = (
                await session.execute(
                    text(
                        """
                        SELECT match_id, winner, COUNT(*) AS n
                        FROM parser.games
                        WHERE match_id = ANY(:match_ids)
                          AND winner IS NOT NULL
                        GROUP BY match_id, winner
                        """
                    ),
                    {"match_ids": match_ids},
                )
            ).all()
        by_match: dict[Any, dict[str, int]] = {}
        for mid, gwinner, n in game_win_rows:
            by_match.setdefault(mid, {})[str(gwinner)] = int(n)
        for mid in match_ids:
            wins_by_player = by_match.get(mid, {})
            mt = match_tied_by_id.get(mid, False)
            if _is_true_draw(wins_by_player, match_tied=mt):
                draw_match_ids.add(mid)

    # Post-filter by result if requested (W/L/D classification needs
    # game-winner counts which are expensive to do in SQL; since we're
    # paginated and the filter is rare, we accept slightly imprecise
    # total counts when a result filter is active).
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
            row_review_status,
            row_review_reason,
            _row_match_tied,
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
            is_draw=match_id in draw_match_ids,
            review_status=row_review_status,
            review_reason=row_review_reason,
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
            elif result_key in ("d", "draws") and item.is_draw:
                filtered.append(item)
        items = filtered

    return AdminMatchListResponse(matches=items, total=total, page=page, per_page=per_page)


# ---------------------------------------------------------------------------
# Admin match review — holding pen verdicts
# ---------------------------------------------------------------------------


# Values an admin can set via POST /admin/matches/{id}/review. ``None``
# (encoded as ``null`` in JSON) accepts a held-back parse and makes it
# user-visible. ``'pending_review'`` re-flags a normal row. ``'rejected'``
# permanently discards a held parse from users + analytics.
_VALID_REVIEW_VERDICTS: set[str | None] = {None, "pending_review", "rejected"}


@admin_router.post("/matches/{match_id}/review", response_model=AdminMatchItem)
async def admin_update_match_review_status(
    match_id: uuid.UUID,
    body: MatchReviewRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> AdminMatchItem:
    """Set the holding-pen verdict on a single match.

    ``review_status=null`` accepts the parse (back to user-visible).
    ``'rejected'`` permanently discards. ``'pending_review'`` flags a
    normal row for admin re-review. Other values are 422.
    """
    verdict = body.review_status
    if verdict not in _VALID_REVIEW_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_review_status",
                "allowed": [None, "pending_review", "rejected"],
            },
        )
    sm = get_sessionmaker()
    async with sm() as session:
        result = await session.execute(
            text("UPDATE parser.matches SET review_status = :rs WHERE id = :mid RETURNING id"),
            {"rs": verdict, "mid": match_id},
        )
        updated = result.one_or_none()
        if updated is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "match_not_found"},
            )
        await session.commit()
        # Cache invalidation — clear the match's user's analytics
        # summary so the dashboard recomputes with the new visibility.
        # Best-effort; the user-facing endpoints already filter live.
        try:
            owner_row = (
                await session.execute(
                    text("SELECT user_id FROM parser.matches WHERE id = :mid"),
                    {"mid": match_id},
                )
            ).scalar_one_or_none()
        except Exception:  # noqa: BLE001
            owner_row = None
        # Re-read the row so the caller gets a coherent post-update view
        # alongside the user_email and computed is_draw flag.
        row = (
            await session.execute(
                text(
                    """
                    SELECT m.id, m.user_id, u.email, m.format, m.players,
                           m.match_result, m.winner, m.game_count,
                           COALESCE(m.played_at, m.parsed_at) AS played_at,
                           m.review_status,
                           m.review_reason,
                           m.match_tied
                    FROM parser.matches m
                    LEFT JOIN auth.users u ON u.id = m.user_id
                    WHERE m.id = :mid
                    """
                ),
                {"mid": match_id},
            )
        ).one()
        # Recompute is_draw the same way the list endpoint does.
        game_win_rows = (
            await session.execute(
                text(
                    """
                    SELECT winner, COUNT(*) AS n
                    FROM parser.games
                    WHERE match_id = :mid AND winner IS NOT NULL
                    GROUP BY winner
                    """
                ),
                {"mid": match_id},
            )
        ).all()
    wins_by_player = {str(w): int(n) for w, n in game_win_rows}
    is_draw_flag = _is_true_draw(wins_by_player, match_tied=bool(row[11]))
    if owner_row is not None:
        try:
            redis_client = await get_redis(get_settings().redis_url)
            await invalidate_user(redis_client, int(owner_row))
        except Exception:  # noqa: BLE001
            _log.debug("review-status cache invalidate failed user_id=%s", owner_row)
    return AdminMatchItem(
        match_id=str(row[0]),
        user_id=int(row[1]),
        user_email=row[2],
        format=row[3],
        players=[str(p) for p in (row[4] or [])],
        match_result=row[5],
        winner=row[6],
        game_count=int(row[7]) if row[7] else 0,
        played_at=row[8],
        review_status=row[9],
        review_reason=row[10],
        is_draw=is_draw_flag,
    )


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
    # Read the run rows first: get_scraper_run opens its own pooled
    # connection, so calling it inside the session below would hold two
    # connections per scraper for the length of an admin page load.
    runs = {
        name: scraper_run_status_fields(await get_scraper_run(name)) for name in _KNOWN_SCRAPERS
    }
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
            run = runs[name]
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
                    is_running=bool(run["is_running"]),
                    running_since=run["running_since"],
                    run_trigger=run["run_trigger"],
                    run_id=run["run_id"],
                    last_heartbeat_at=run["last_heartbeat_at"],
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
        # Upsert the config row.  On conflict, prefer the provided
        # value, then the existing DB value, then the default — so a
        # toggle-only PATCH never clobbers the stored interval.
        sets: list[str] = []
        params: dict[str, Any] = {"name": name}
        if body.enabled is not None:
            sets.append("enabled = :enabled")
            params["enabled"] = body.enabled
        if body.interval_hours is not None:
            sets.append("interval_hours = :interval_hours")
            params["interval_hours"] = body.interval_hours
        else:
            sets.append("interval_hours = COALESCE(analytics.scraper_config.interval_hours, 24)")
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
    run = scraper_run_status_fields(await get_scraper_run(name))
    return ScraperConfigResponse(
        scraper_name=name,
        enabled=bool(config_row[0]),
        interval_hours=int(config_row[1]),
        last_run_at=health.get("last_run_at"),
        last_success_at=health.get("last_success_at"),
        consecutive_failures=health.get("consecutive_failures", 0),
        is_broken=health.get("is_broken", False),
        last_error=health.get("last_error"),
        is_running=bool(run["is_running"]),
        running_since=run["running_since"],
        run_trigger=run["run_trigger"],
        run_id=run["run_id"],
        last_heartbeat_at=run["last_heartbeat_at"],
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
        total = int((await session.execute(text(f"SELECT COUNT(*) FROM {table}"))).scalar_one())
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


def _decklist_card_count(decklist: Any) -> int:
    """Sum the quantities in a ``{card_name: qty}`` decklist.

    Used so the dashboard can show "60/15" for results that have cards
    but no archetype name (MTGO, which doesn't tag deck archetypes).
    Tolerant of None, non-dict values, and non-integer qty fields.
    """
    if not isinstance(decklist, dict):
        return 0
    total = 0
    for qty in decklist.values():
        try:
            total += int(qty)
        except (TypeError, ValueError):
            continue
    return total


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
                        "main_card_count": _decklist_card_count(r[3]),
                        "sideboard_card_count": _decklist_card_count(r[4]),
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
                        "main_card_count": _decklist_card_count(r[2]),
                        "sideboard_card_count": _decklist_card_count(r[3]),
                    }
                    for r in result_rows
                ],
            }


# ---------------------------------------------------------------------------
# ML Classifier admin endpoints (F9)
# ---------------------------------------------------------------------------


@admin_router.post("/classifier/retrain", response_model=TrainResult, status_code=202)
async def classifier_retrain(
    background_tasks: BackgroundTasks,
    _admin: AuthenticatedUser = Depends(require_admin),
) -> TrainResult:
    """Trigger ML model retraining in the background.

    Returns 202 immediately with a placeholder result; the actual
    training runs asynchronously. Check ``/classifier/status`` to
    see when the model has been updated.
    """

    async def _do_retrain() -> None:
        sm = get_sessionmaker()
        async with sm() as session:
            result = await ml_retrain(session)
        _log.info("ML retrain completed: %s", result.message)

    background_tasks.add_task(_do_retrain)
    return TrainResult(message="retraining started")


@admin_router.get("/classifier/status", response_model=ClassifierStatus)
async def classifier_status(
    _admin: AuthenticatedUser = Depends(require_admin),
) -> ClassifierStatus:
    """Return the current ML classifier model status."""
    s = ml_get_status()
    return ClassifierStatus(
        loaded=s["loaded"],
        sample_count=s["sample_count"],
        label_count=s["label_count"],
        last_trained_at=s["last_trained_at"],
    )


# ---------------------------------------------------------------------------
# Canonical archetypes CRUD (F9)
# ---------------------------------------------------------------------------


def _canonical_record(row: CanonicalArchetype) -> CanonicalArchetypeRecord:
    return CanonicalArchetypeRecord(
        id=row.id,
        canonical_name=row.canonical_name,
        format=row.format,
        variant_tags=row.variant_tags,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@admin_router.get("/canonical-archetypes", response_model=CanonicalArchetypeListView)
async def list_canonical_archetypes(
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> CanonicalArchetypeListView:
    rows = (
        (
            await db.execute(
                select(CanonicalArchetype).order_by(
                    CanonicalArchetype.format, CanonicalArchetype.canonical_name
                )
            )
        )
        .scalars()
        .all()
    )
    total = int(
        (await db.execute(select(func.count()).select_from(CanonicalArchetype))).scalar_one()
    )
    return CanonicalArchetypeListView(archetypes=[_canonical_record(r) for r in rows], total=total)


@admin_router.post(
    "/canonical-archetypes",
    response_model=CanonicalArchetypeRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_canonical_archetype(
    body: CanonicalArchetypeCreate,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> CanonicalArchetypeRecord:
    row = CanonicalArchetype(
        id=uuid.uuid4(),
        canonical_name=body.canonical_name,
        format=body.format,
        variant_tags=body.variant_tags,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _canonical_record(row)


@admin_router.put("/canonical-archetypes/{archetype_id}", response_model=CanonicalArchetypeRecord)
async def update_canonical_archetype(
    archetype_id: uuid.UUID,
    body: CanonicalArchetypeCreate,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> CanonicalArchetypeRecord:
    row = (
        await db.execute(select(CanonicalArchetype).where(CanonicalArchetype.id == archetype_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "canonical_archetype_not_found"},
        )
    row.canonical_name = body.canonical_name
    row.format = body.format
    row.variant_tags = body.variant_tags
    row.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(row)
    return _canonical_record(row)


@admin_router.delete("/canonical-archetypes/{archetype_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_canonical_archetype(
    archetype_id: uuid.UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> None:
    result = await db.execute(
        delete(CanonicalArchetype).where(CanonicalArchetype.id == archetype_id)
    )
    await db.commit()
    rowcount: int = result.rowcount  # type: ignore[attr-defined]
    if rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "canonical_archetype_not_found"},
        )


# ---------------------------------------------------------------------------
# Label mappings CRUD (F9)
# ---------------------------------------------------------------------------


@admin_router.get("/label-mappings", response_model=ArchetypeLabelMappingListView)
async def list_label_mappings(
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
    canonical_id: Annotated[uuid.UUID | None, Query()] = None,
) -> ArchetypeLabelMappingListView:
    query = select(ArchetypeLabelMapping)
    if canonical_id is not None:
        query = query.where(ArchetypeLabelMapping.canonical_id == canonical_id)
    query = query.order_by(ArchetypeLabelMapping.scraped_label)

    rows = (await db.execute(query)).scalars().all()

    # Count
    count_query = select(func.count()).select_from(ArchetypeLabelMapping)
    if canonical_id is not None:
        count_query = count_query.where(ArchetypeLabelMapping.canonical_id == canonical_id)
    total = int((await db.execute(count_query)).scalar_one())

    # Eagerly resolve canonical names for the response.
    canonical_ids = {r.canonical_id for r in rows}
    canonical_map: dict[uuid.UUID, str] = {}
    if canonical_ids:
        ca_rows = (
            await db.execute(
                select(CanonicalArchetype.id, CanonicalArchetype.canonical_name).where(
                    CanonicalArchetype.id.in_(canonical_ids)
                )
            )
        ).all()
        canonical_map = {r[0]: r[1] for r in ca_rows}

    mappings = [
        ArchetypeLabelMappingRecord(
            id=r.id,
            scraped_label=r.scraped_label,
            canonical_id=r.canonical_id,
            canonical_name=canonical_map.get(r.canonical_id),
            created_at=r.created_at,
        )
        for r in rows
    ]
    return ArchetypeLabelMappingListView(mappings=mappings, total=total)


@admin_router.post(
    "/label-mappings",
    response_model=ArchetypeLabelMappingRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_label_mapping(
    body: ArchetypeLabelMappingCreate,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> ArchetypeLabelMappingRecord:
    # Verify canonical archetype exists.
    ca = (
        await db.execute(
            select(CanonicalArchetype).where(CanonicalArchetype.id == body.canonical_id)
        )
    ).scalar_one_or_none()
    if ca is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "canonical_archetype_not_found"},
        )
    row = ArchetypeLabelMapping(
        scraped_label=body.scraped_label,
        canonical_id=body.canonical_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return ArchetypeLabelMappingRecord(
        id=row.id,
        scraped_label=row.scraped_label,
        canonical_id=row.canonical_id,
        canonical_name=ca.canonical_name,
        created_at=row.created_at,
    )


@admin_router.delete("/label-mappings/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_label_mapping(
    mapping_id: int,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> None:
    result = await db.execute(
        delete(ArchetypeLabelMapping).where(ArchetypeLabelMapping.id == mapping_id)
    )
    await db.commit()
    rowcount: int = result.rowcount  # type: ignore[attr-defined]
    if rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "label_mapping_not_found"},
        )


app.include_router(admin_router)


@app.get("/healthz")
@app.get("/analytics/healthz")
async def healthz() -> JSONResponse:
    from common.health import check_db, check_redis, evaluate

    redis_client = await get_redis(get_settings().redis_url)
    report = await evaluate(
        [
            check_db(get_sessionmaker()),
            check_redis(redis_client),
        ]
    )
    return JSONResponse(
        content=report.to_dict(SERVICE_NAME),
        status_code=report.http_status,
    )
