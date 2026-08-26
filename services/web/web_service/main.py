"""Web service — admin UI shell + browser auth.

This service serves the browser-facing admin UI. Browser sessions use
a cookie-carried JWT (``da_session``); API consumers continue to hit
/auth/* on the auth service with a Bearer header. The two paths are
independent and coexist in the compose stack.
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from common.logging import configure_logging
from common.metrics import start_metrics_server
from web_service import analytics_client, auth_client, parser_client
from web_service import csrf as _csrf_mod
from web_service.deps import (
    BrowserAuthRedirect,
    BrowserUser,
    browser_auth_redirect_handler,
    get_current_browser_user,
    get_current_browser_user_any_scope,
    get_verifier,
)
from web_service.settings import WebSettings, get_settings
from web_service.urls import filter_url

SERVICE_NAME = "web"
configure_logging(SERVICE_NAME)
_log = logging.getLogger("web.main")

_PACKAGE_ROOT = Path(__file__).resolve().parent
_TEMPLATES_DIR = _PACKAGE_ROOT / "templates"
_STATIC_DIR = _PACKAGE_ROOT / "static"


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    start_metrics_server(SERVICE_NAME, get_settings().metrics_port)
    yield


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
templates.env.globals["app_version"] = os.environ.get("APP_VERSION", "dev")
templates.env.globals["filter_url"] = filter_url
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Browser-auth redirect handler — converts BrowserAuthRedirect into a
# 302 to /login (or /settings/password for password-change scope).
app.add_exception_handler(BrowserAuthRedirect, browser_auth_redirect_handler)


# ---------------------------------------------------------------------------
# MOTD cache — short TTL so updates propagate quickly
# ---------------------------------------------------------------------------

_motd_cache: auth_client.MotdResult | None = None
_motd_cache_ts: float = 0.0
_MOTD_CACHE_TTL_SECONDS = 30.0


async def _get_cached_motd(settings_obj: WebSettings) -> auth_client.MotdResult:
    """Return the current MOTD, using a 30-second in-memory cache."""
    global _motd_cache, _motd_cache_ts
    now = time.monotonic()
    if _motd_cache is not None and (now - _motd_cache_ts) < _MOTD_CACHE_TTL_SECONDS:
        return _motd_cache
    result = await auth_client.public_get_motd(settings_obj.auth_service_url)
    _motd_cache = result
    _motd_cache_ts = now
    return result


def _reset_motd_cache() -> None:
    """Test hook + post-update invalidation."""
    global _motd_cache, _motd_cache_ts
    _motd_cache = None
    _motd_cache_ts = 0.0


@app.middleware("http")
async def csrf_protection_middleware(request: Request, call_next: Any) -> Response:
    """CSRF double-submit cookie enforcement.

    Registered as a middleware wrapper so it runs for every request.
    The actual logic lives in :mod:`web_service.csrf`.
    """
    return await _csrf_mod.csrf_middleware(request, call_next)


@app.middleware("http")
async def inject_motd_middleware(request: Request, call_next: Any) -> Response:
    """Fetch the MOTD once per request and stash it on request.state."""
    path = request.url.path
    if path.startswith("/static") or path.endswith("/healthz"):
        return await call_next(request)
    try:
        motd = await _get_cached_motd(get_settings())
    except Exception:  # noqa: BLE001
        motd = auth_client.MotdResult(active=False)
    request.state.motd = motd
    return await call_next(request)


# Patch Jinja2Templates to auto-inject ``motd`` into every render context.
_original_template_response = templates.TemplateResponse


def _patched_template_response(
    request_or_name: Any,
    name_or_context: Any = None,
    context: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Response:
    """Wrapper that injects ``motd`` and ``csrf_token`` into every template context."""
    if isinstance(request_or_name, Request):
        req = request_or_name
        tpl_name = name_or_context
        ctx = context or {}
    else:
        tpl_name = request_or_name
        ctx = name_or_context if isinstance(name_or_context, dict) else (context or {})
        req = ctx.get("request")  # type: ignore[assignment]
    if req is not None and hasattr(req, "state") and hasattr(req.state, "motd"):
        ctx.setdefault("motd", req.state.motd)
    else:
        ctx.setdefault("motd", None)
    if req is not None and hasattr(req, "state") and hasattr(req.state, "csrf_token"):
        ctx.setdefault("csrf_token", req.state.csrf_token)
    else:
        ctx.setdefault("csrf_token", "")
    return _original_template_response(req, tpl_name, ctx, **kwargs)


templates.TemplateResponse = _patched_template_response  # type: ignore[assignment]


@app.get("/healthz")
@app.get("/web/healthz")
async def healthz() -> JSONResponse:
    from common.health import check_http, evaluate

    settings = get_settings()
    report = await evaluate(
        [
            check_http(f"{settings.auth_service_url}/healthz", "auth"),
            check_http(f"{settings.analytics_service_url}/healthz", "analytics"),
            check_http(f"{settings.parser_service_url}/healthz", "parser"),
        ]
    )
    return JSONResponse(
        content=report.to_dict(SERVICE_NAME),
        status_code=report.http_status,
    )


_ADMIN_LANDING_PATH = "/admin/users"


def _safe_next(next_value: str | None) -> str:
    """Only allow internal absolute paths as post-login destinations.

    Rejects anything that could render as protocol-relative or
    scheme-prefixed after browser URL-normalization. Anything
    suspicious falls back to /dashboard.
    """
    if not next_value:
        return "/dashboard"
    if not next_value.startswith("/"):
        return "/dashboard"
    # Protocol-relative (``//host``) or backslash-smuggled variants
    # (``/\host``) — Chrome and others normalize ``\`` to ``/`` in
    # URL paths, so ``/\\evil.com`` becomes ``//evil.com`` when the
    # browser follows the redirect.
    if next_value.startswith("//") or next_value.startswith("/\\"):
        return "/dashboard"
    if "\\" in next_value:
        return "/dashboard"
    return next_value


def _role_from_token(token: str) -> str | None:
    """Decode a freshly-issued access token's role claim.

    Used by /login to land admins on /admin/users instead of
    /dashboard. Returns None if the token can't be verified — the
    caller falls back to the standard /dashboard target so a transient
    verifier glitch never strands a user mid-login.
    """
    try:
        claims = get_verifier().verify(token)
    except Exception:  # noqa: BLE001 — verification problems mean "unknown role"
        return None
    role = claims.get("role")
    return str(role) if role else None


def _set_session_cookie(response: Response, token: str, ttl_seconds: int) -> None:
    response.set_cookie(
        key=get_settings().session_cookie_name,
        value=token,
        max_age=ttl_seconds,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    # Match the attributes used on set_cookie so intermediaries /
    # browsers that attribute-match the deletion find the right
    # cookie to expire.
    response.delete_cookie(
        key=get_settings().session_cookie_name,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
    )


@app.get("/", response_class=HTMLResponse)
async def landing(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Public landing page.

    Logged-in users are redirected straight to /dashboard (or the admin
    panel for admins). Everyone else sees the marketing landing page.
    """
    try:
        user = await get_current_browser_user(request, settings)
    except BrowserAuthRedirect:
        # No valid session — render the public landing page.
        mode = await auth_client.public_get_registration_mode(settings.auth_service_url)
        return templates.TemplateResponse(
            request,
            "landing.html",
            {"user": None, "registration_open": mode != "closed"},
        )
    # Logged in — bounce to the appropriate home.
    if user.role == "admin":
        return RedirectResponse(url=_ADMIN_LANDING_PATH, status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str | None = None) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": next or "", "error": None, "email": ""},
    )


@app.post("/login")
async def login_submit(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "",
    settings: WebSettings = Depends(get_settings),
) -> Response:
    try:
        result = await auth_client.login(settings.auth_service_url, email, password)
    except auth_client.InvalidCredentials:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"next": next, "error": "Invalid credentials", "email": email},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    except auth_client.AuthClientError:
        _log.exception("auth service login call failed")
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next": next,
                "error": "Authentication service unavailable. Please try again.",
                "email": email,
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # must_change_password sessions get a short-scoped token; send
    # them straight to the password page regardless of ?next=.
    if result.must_change_password:
        redirect = RedirectResponse(url="/settings/password", status_code=status.HTTP_303_SEE_OTHER)
    else:
        # Admins land on the admin panel by default — self-service
        # routes are off-limits to them under the W3.6 hard split. A
        # caller-supplied ?next= still wins so an admin who clicked a
        # deep link before logging in can finish the navigation.
        if next:
            target = _safe_next(next)
        elif _role_from_token(result.access_token) == "admin":
            target = _ADMIN_LANDING_PATH
        else:
            target = "/dashboard"
        redirect = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)

    _set_session_cookie(redirect, result.access_token, result.expires_in)
    return redirect


_DASHBOARD_DEFAULT_PER_PAGE = 20
_DASHBOARD_MAX_PER_PAGE = 100
_OPPONENT_DEFAULT_PER_PAGE = 20
_OPPONENT_MAX_PER_PAGE = 100


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    format: Annotated[str, Query(alias="format")] = "",
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
) -> Response:
    if user.role == "admin":
        return RedirectResponse(url=_ADMIN_LANDING_PATH, status_code=status.HTTP_302_FOUND)

    format_filter = format or None
    df = date_from or None
    dt = date_to or None

    stats_summary: Any = None
    format_stats: list[Any] = []
    stats_error = False
    play_draw_stats: Any = None
    preboard_postboard_stats: Any = None
    mulligan_stats: Any = None
    card_stats: Any = None
    try:
        stats_summary = await analytics_client.get_stats_summary(
            settings.analytics_service_url, user.token, date_from=df, date_to=dt
        )
        format_stats = await analytics_client.get_stats_by_format(
            settings.analytics_service_url, user.token, date_from=df, date_to=dt
        )
    except analytics_client.AnalyticsForbidden:
        # Treat as logged-out: bounce to /login so the user can re-auth.
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics stats call failed; rendering dashboard with error banner")
        stats_error = True

    try:
        play_draw_stats = await analytics_client.get_play_draw_stats(
            settings.analytics_service_url,
            user.token,
            format_filter=format_filter,
            date_from=df,
            date_to=dt,
        )
    except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
        _log.debug("play/draw stats unavailable")

    try:
        preboard_postboard_stats = await analytics_client.get_preboard_postboard_stats(
            settings.analytics_service_url,
            user.token,
            format_filter=format_filter,
            date_from=df,
            date_to=dt,
        )
    except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
        _log.debug("preboard/postboard stats unavailable")

    try:
        mulligan_stats = await analytics_client.get_mulligan_stats(
            settings.analytics_service_url,
            user.token,
            format_filter=format_filter,
            date_from=df,
            date_to=dt,
        )
    except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
        _log.debug("mulligan stats unavailable")

    # Card stats. Page size matches the HTMX partial so pagination stays
    # consistent when the user clicks "Next".
    try:
        card_stats = await analytics_client.get_card_stats(
            settings.analytics_service_url,
            user.token,
            per_page=_CARD_PERF_PER_PAGE,
            format_filter=format_filter,
            date_from=df,
            date_to=dt,
        )
    except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
        _log.debug("card stats unavailable")

    # When a format is selected, swap in that format's row from the
    # by-format breakdown as the headline numbers (Total / Record /
    # Win rate). Falls back to the overall summary when no row matches.
    filtered_summary: Any = None
    if format_filter:
        for row in format_stats:
            if row.format_ == format_filter:
                filtered_summary = row
                break

    # Fetch B&R events for the selected format (epoch presets in date filter)
    bnr_events: list[Any] = []
    if format_filter:
        try:
            bnr_events = await analytics_client.get_bnr_events_by_format(
                settings.analytics_service_url, user.token, format_filter
            )
        except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
            _log.debug("bnr events unavailable for format %s", format_filter)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "stats_summary": stats_summary,
            "format_stats": format_stats,
            "stats_error": stats_error,
            "play_draw_stats": play_draw_stats,
            "preboard_postboard_stats": preboard_postboard_stats,
            "mulligan_stats": mulligan_stats,
            "card_stats": card_stats,
            "format_filter": format,
            "filtered_summary": filtered_summary,
            "date_from": date_from,
            "date_to": date_to,
            "bnr_events": bnr_events,
        },
    )


# ---------------------------------------------------------------------------
# Match History page
# ---------------------------------------------------------------------------


@app.get("/matches", response_class=HTMLResponse)
async def match_history_page(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=_DASHBOARD_MAX_PER_PAGE)] = _DASHBOARD_DEFAULT_PER_PAGE,
    opp_page: Annotated[int, Query(ge=1)] = 1,
    format: Annotated[str, Query(alias="format")] = "",
    opponent: Annotated[str, Query()] = "",
    result: Annotated[str, Query()] = "",
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
) -> Response:
    if user.role == "admin":
        return RedirectResponse(url=_ADMIN_LANDING_PATH, status_code=status.HTTP_302_FOUND)

    opponent_stats: list[Any] = []
    match_list: Any = None
    stats_error = False
    try:
        opponent_stats = await analytics_client.get_stats_by_opponent(
            settings.analytics_service_url, user.token
        )
        match_list = await analytics_client.get_match_list(
            settings.analytics_service_url,
            user.token,
            page=page,
            per_page=per_page,
            format_filter=format or None,
            opponent=opponent or None,
            result=result or None,
            date_from=date_from or None,
            date_to=date_to or None,
        )
    except analytics_client.AnalyticsForbidden:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics stats call failed on match history page")
        stats_error = True

    filters = {
        "format": format,
        "opponent": opponent,
        "result": result,
        "date_from": date_from,
        "date_to": date_to,
    }
    filter_qs = urlencode({k: v for k, v in filters.items() if v})

    opp_per_page = _OPPONENT_DEFAULT_PER_PAGE
    opp_offset = (opp_page - 1) * opp_per_page
    opponent_page = opponent_stats[opp_offset : opp_offset + opp_per_page]

    return templates.TemplateResponse(
        request,
        "match_history.html",
        {
            "user": user,
            "opponent_stats": opponent_stats,
            "opponent_page": opponent_page,
            "opp_page": opp_page,
            "opp_per_page": opp_per_page,
            "match_list": match_list,
            "stats_error": stats_error,
            "page": page,
            "per_page": per_page,
            "filters": filters,
            "filter_qs": filter_qs,
        },
    )


# ---------------------------------------------------------------------------
# Dashboard HTMX partials — format drill-down cascade
# ---------------------------------------------------------------------------


@app.get("/dashboard/partials/play-draw", response_class=HTMLResponse)
async def dashboard_partial_play_draw(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    format: Annotated[str, Query(alias="format")] = "",
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
) -> Response:
    """HTMX partial: play/draw stats filtered by format and date range."""
    play_draw_stats: Any = None
    try:
        play_draw_stats = await analytics_client.get_play_draw_stats(
            settings.analytics_service_url,
            user.token,
            format_filter=format or None,
            date_from=date_from or None,
            date_to=date_to or None,
        )
    except analytics_client.AnalyticsForbidden:
        return HTMLResponse("<p>Session expired. Please reload the page.</p>", status_code=401)
    except analytics_client.AnalyticsClientError:
        _log.debug("play/draw stats unavailable for format=%s", format)
    return templates.TemplateResponse(
        request,
        "_partials_play_draw.html",
        {"play_draw_stats": play_draw_stats},
    )


@app.get("/dashboard/partials/preboard-postboard", response_class=HTMLResponse)
async def dashboard_partial_preboard_postboard(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    format: Annotated[str, Query(alias="format")] = "",
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
) -> Response:
    """HTMX partial: pre-board vs post-board stats filtered by format and date range."""
    preboard_postboard_stats: Any = None
    try:
        preboard_postboard_stats = await analytics_client.get_preboard_postboard_stats(
            settings.analytics_service_url,
            user.token,
            format_filter=format or None,
            date_from=date_from or None,
            date_to=date_to or None,
        )
    except analytics_client.AnalyticsForbidden:
        return HTMLResponse("<p>Session expired. Please reload the page.</p>", status_code=401)
    except analytics_client.AnalyticsClientError:
        _log.debug("preboard/postboard stats unavailable for format=%s", format)
    return templates.TemplateResponse(
        request,
        "_partials_preboard_postboard.html",
        {"preboard_postboard_stats": preboard_postboard_stats},
    )


@app.get("/dashboard/partials/mulligans", response_class=HTMLResponse)
async def dashboard_partial_mulligans(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    format: Annotated[str, Query(alias="format")] = "",
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
) -> Response:
    """HTMX partial: mulligan analysis filtered by format and date range."""
    mulligan_stats: Any = None
    try:
        mulligan_stats = await analytics_client.get_mulligan_stats(
            settings.analytics_service_url,
            user.token,
            format_filter=format or None,
            date_from=date_from or None,
            date_to=date_to or None,
        )
    except analytics_client.AnalyticsForbidden:
        return HTMLResponse("<p>Session expired. Please reload the page.</p>", status_code=401)
    except analytics_client.AnalyticsClientError:
        _log.debug("mulligan stats unavailable for format=%s", format)
    return templates.TemplateResponse(
        request,
        "_partials_mulligans.html",
        {"mulligan_stats": mulligan_stats},
    )


_CARD_PERF_PER_PAGE = 10

# Mirrors the analytics-side allowlist; kept here so we can validate
# user-supplied query params before passing them to analytics, and fall
# back to defaults rather than 400ing the dashboard.
_CARD_SORT_COLUMNS = frozenset({"card_name", "games", "win_rate", "avg_cast_turn"})
_CARD_SORT_DIRS = frozenset({"asc", "desc"})
_CARD_SORT_DEFAULT = "games"
_CARD_DIR_DEFAULT = "desc"


@app.get("/dashboard/partials/card-performance", response_class=HTMLResponse)
async def dashboard_partial_card_performance(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    format: Annotated[str, Query(alias="format")] = "",
    page: Annotated[int, Query(ge=1)] = 1,
    sort: Annotated[str, Query()] = _CARD_SORT_DEFAULT,
    dir: Annotated[str, Query()] = _CARD_DIR_DEFAULT,
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
) -> Response:
    """HTMX partial: card performance filtered by format and date range, paginated.

    ``sort`` + ``dir`` come from header clicks in the partial. Invalid
    values fall back to the defaults (``games`` desc) rather than 400 —
    the user clicked something we don't recognize, not a hand-crafted
    payload.
    """
    if sort not in _CARD_SORT_COLUMNS:
        sort = _CARD_SORT_DEFAULT
    if dir not in _CARD_SORT_DIRS:
        dir = _CARD_DIR_DEFAULT

    card_stats: Any = None
    try:
        card_stats = await analytics_client.get_card_stats(
            settings.analytics_service_url,
            user.token,
            page=page,
            per_page=_CARD_PERF_PER_PAGE,
            sort_by=sort,
            sort_dir=dir,
            format_filter=format or None,
            date_from=date_from or None,
            date_to=date_to or None,
        )
    except analytics_client.AnalyticsForbidden:
        return HTMLResponse("<p>Session expired. Please reload the page.</p>", status_code=401)
    except analytics_client.AnalyticsClientError:
        _log.debug("card stats unavailable for format=%s", format)
    return templates.TemplateResponse(
        request,
        "_partials_card_performance.html",
        {
            "card_stats": card_stats,
            "format_filter": format,
            "current_sort": sort,
            "current_dir": dir,
            "date_from": date_from,
            "date_to": date_to,
        },
    )


@app.get("/settings/password", response_class=HTMLResponse)
async def password_form(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user_any_scope),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "password.html",
        {"user": user, "must_change": user.must_change_password, "error": None},
    )


@app.post("/settings/password")
async def password_submit(
    request: Request,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user_any_scope),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    def _render_error(message: str, code: int = status.HTTP_400_BAD_REQUEST) -> Response:
        return templates.TemplateResponse(
            request,
            "password.html",
            {
                "user": user,
                "must_change": user.must_change_password,
                "error": message,
            },
            status_code=code,
        )

    if new_password != confirm_password:
        return _render_error("New password and confirmation do not match.")
    if not new_password:
        return _render_error("New password is required.")

    try:
        ok, err = await auth_client.change_password(
            settings.auth_service_url,
            user.token,
            current_password,
            new_password,
        )
    except auth_client.AuthForbidden:
        _log.info("password.change.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth service change_password call failed")
        return _render_error(
            "Authentication service unavailable. Please try again.",
            code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if not ok:
        if err == "weak_password":
            return _render_error("New password does not meet policy requirements.")
        return _render_error("Current password is incorrect.")

    # Auth revokes all sessions on successful password change, so the
    # current cookie is now dead. Re-login to get a fresh full-scope
    # token and set a new cookie before bouncing to the dashboard.
    try:
        fresh = await auth_client.login(settings.auth_service_url, user.email or "", new_password)
    except (auth_client.InvalidCredentials, auth_client.AuthClientError):
        # Fall back to /login; user can re-enter credentials. Happens
        # when the JWT didn't carry an email claim (rolling upgrade)
        # or the auth service is briefly unreachable.
        _log.warning("post-password-change re-login failed; clearing cookie and bouncing to /login")
        redirect = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        _clear_session_cookie(redirect)
        return redirect

    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(redirect, fresh.access_token, fresh.expires_in)
    return redirect


def _bounce_admin_to_panel(user: BrowserUser) -> Response | None:
    """Redirect admins away from self-service routes.

    Admins under W3.6 hard role separation have no self-service
    surface — every /profile* route bounces them straight to the
    admin panel landing.
    """
    if user.role == "admin":
        return RedirectResponse(url=_ADMIN_LANDING_PATH, status_code=status.HTTP_302_FOUND)
    return None


@app.get("/profile", response_class=HTMLResponse)
async def profile(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        me = await auth_client.get_me(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("profile.get_me.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth /me call failed")
        return _service_unavailable(request, user)
    return templates.TemplateResponse(
        request,
        "profile.html",
        {"user": user, "me": me},
    )


@app.get("/profile/edit", response_class=HTMLResponse)
async def profile_edit_form(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        me = await auth_client.get_me(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("profile.edit.get_me.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth /me call failed")
        return _service_unavailable(
            request,
            user,
            "profile_edit.html",
            {"email": ""},
        )
    names_str = ", ".join(me.mtgo_usernames) if me.mtgo_usernames else ""
    return templates.TemplateResponse(
        request,
        "profile_edit.html",
        {
            "user": user,
            "email": me.email,
            "mtgo_usernames_str": names_str,
            "error": None,
        },
    )


@app.get("/profile/username-suggestions")
async def profile_username_suggestions(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """JSON endpoint returning MTGO username suggestions from match data."""
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        suggestions = await analytics_client.get_username_suggestions(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        return JSONResponse([], status_code=status.HTTP_401_UNAUTHORIZED)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /stats/username-suggestion call failed")
        return JSONResponse([], status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

    return JSONResponse(
        [{"username": s.username, "match_count": s.match_count} for s in suggestions]
    )


@app.post("/profile/edit")
async def profile_edit_submit(
    request: Request,
    email: Annotated[str, Form()],
    mtgo_usernames: Annotated[str, Form()] = "",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    submitted = email.strip()
    names_list = [n.strip() for n in mtgo_usernames.split(",") if n.strip()]

    def _render_error(message: str, code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "profile_edit.html",
            {
                "user": user,
                "email": submitted,
                "mtgo_usernames_str": mtgo_usernames,
                "error": message,
            },
            status_code=code,
        )

    if not submitted:
        return _render_error("Email is required.", status.HTTP_400_BAD_REQUEST)

    try:
        result = await auth_client.update_me(
            settings.auth_service_url,
            user.token,
            submitted,
            mtgo_usernames=names_list,
        )
    except auth_client.AuthForbidden:
        _log.info("profile.edit.update_me.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth PATCH /me call failed")
        return templates.TemplateResponse(
            request,
            "profile_edit.html",
            {
                "user": user,
                "email": submitted,
                "error": "Authentication service unavailable. Please try again.",
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if result.ok:
        # Email is a JWT claim — auth re-mints the access token; we
        # rotate the session cookie so subsequent requests resolve the
        # new identity (avoids a stale-claim → /login bounce on the
        # next password-change re-login).
        redirect = RedirectResponse(url="/profile", status_code=status.HTTP_303_SEE_OTHER)
        if result.access_token and result.expires_in is not None:
            _set_session_cookie(redirect, result.access_token, result.expires_in)
        return redirect
    if result.error == "email_taken":
        return _render_error(
            "That email is already in use by another account.",
            status.HTTP_409_CONFLICT,
        )
    if result.error == "invalid_email":
        return _render_error(
            "Email address is not valid.",
            status.HTTP_400_BAD_REQUEST,
        )
    return _render_error(
        "Could not update profile.",
        status.HTTP_400_BAD_REQUEST,
    )


_PROFILE_AGENTS_DEFAULT_PER_PAGE = 50
# Matches auth-side `_ME_AGENTS_MAX_LIMIT` so per_page above this 422s here
# rather than getting silently clamped at the auth boundary.
_PROFILE_AGENTS_MAX_PER_PAGE = 200


@app.get("/profile/agents", response_class=HTMLResponse)
async def profile_agents(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_PROFILE_AGENTS_MAX_PER_PAGE),
    ] = _PROFILE_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    offset = (page - 1) * per_page
    try:
        agents, total = await auth_client.list_my_agents(
            settings.auth_service_url, user.token, limit=per_page, offset=offset
        )
    except auth_client.AuthForbidden:
        _log.info("profile.agents.list.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth /me/agents call failed")
        return _service_unavailable(
            request,
            user,
            "profile_agents.html",
            {"agents": [], "page": 1, "total_pages": 0, "total": 0},
        )
    return templates.TemplateResponse(
        request,
        "profile_agents.html",
        {
            "user": user,
            "agents": agents,
            "total": total,
            "page": page,
            "per_page": per_page,
        },
    )


@app.post("/profile/agents/registration-code")
async def profile_agents_generate_code(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        result = await auth_client.mint_registration_code(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("profile.agents.registration_code.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth /agent/registration-code call failed")
        return _service_unavailable(
            request,
            user,
            "profile_agents.html",
            {"agents": [], "page": 1, "total_pages": 0, "total": 0},
        )

    # Re-render the agents page with the freshly minted code. List
    # fetch is best-effort — surfacing the code matters more than the
    # list, so we tolerate an empty list if auth is mid-glitch.
    offset = 0
    per_page = _PROFILE_AGENTS_DEFAULT_PER_PAGE
    try:
        agents, total = await auth_client.list_my_agents(
            settings.auth_service_url, user.token, limit=per_page, offset=offset
        )
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        agents, total = [], 0

    return templates.TemplateResponse(
        request,
        "profile_agents.html",
        {
            "user": user,
            "agents": agents,
            "total": total,
            "page": 1,
            "per_page": per_page,
            "registration_code": result.code,
            "registration_code_expires_at": result.expires_at,
        },
    )


@app.post("/profile/reparse")
async def profile_reparse(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """User self-service: reparse all of the caller's matches.

    On rate-limit hit (429 from parser), render the profile page with a
    friendly error banner instead of bouncing to a 503 page — the user
    just learned they have to wait, that's a soft outcome.
    """
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce

    try:
        result = await parser_client.user_self_service_reparse(
            settings.parser_service_url, user.token
        )
    except parser_client.ParserRateLimited as exc:
        # Format the retry-at timestamp as HH:MM UTC for the banner.
        try:
            retry_dt = datetime.fromisoformat(exc.retry_at.replace("Z", "+00:00"))
            retry_label = retry_dt.strftime("%H:%M UTC")
        except (TypeError, ValueError):
            retry_label = "shortly"
        _log.info(
            "profile.reparse.rate_limited",
            extra={"user_id": user.user_id, "retry_at": exc.retry_at},
        )
        me = None
        with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
            me = await auth_client.get_me(settings.auth_service_url, user.token)
        return templates.TemplateResponse(
            request,
            "profile.html",
            {
                "user": user,
                "me": me,
                "reparse_error": (
                    f"Already reparsed within the last hour. Try again at {retry_label}."
                ),
            },
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
    except parser_client.ParserForbidden:
        _log.info("profile.reparse.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except parser_client.ParserClientError:
        _log.exception("parser POST /parser/me/reparse call failed")
        return Response(
            content="Parser service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    me = None
    with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
        me = await auth_client.get_me(settings.auth_service_url, user.token)
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "user": user,
            "me": me,
            "reparse_result": result,
        },
    )


@app.post("/profile/agents/{agent_id}/reparse")
async def profile_agents_reparse(
    agent_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Force reparse: delete parsed matches uploaded by a specific agent."""
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        result = await parser_client.delete_my_matches(
            settings.parser_service_url, user.token, agent_id=str(agent_id)
        )
    except parser_client.ParserForbidden:
        _log.info("profile.agents.reparse.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except parser_client.ParserClientError:
        _log.exception("parser DELETE /parser/matches call failed")
        return Response(
            content="Parser service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # Re-render the agents page with the reparse result.
    offset = 0
    per_page = _PROFILE_AGENTS_DEFAULT_PER_PAGE
    try:
        agents, total = await auth_client.list_my_agents(
            settings.auth_service_url, user.token, limit=per_page, offset=offset
        )
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        agents, total = [], 0

    return templates.TemplateResponse(
        request,
        "profile_agents.html",
        {
            "user": user,
            "agents": agents,
            "total": total,
            "page": 1,
            "per_page": per_page,
            "reparse_result": result,
        },
    )


@app.post("/profile/agents/{agent_id}/revoke")
async def profile_agents_revoke(
    # Typed UUID rejects malformed IDs at the route boundary with 422,
    # so they never round-trip to auth and surface as a misclassified
    # 503 from the AuthClientError → outage path.
    agent_id: uuid.UUID,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        ok, err = await auth_client.revoke_my_agent(
            settings.auth_service_url, user.token, str(agent_id)
        )
    except auth_client.AuthForbidden:
        _log.info("profile.agents.revoke.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except auth_client.AuthClientError:
        _log.exception("auth /me/agents revoke call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    # 404 still bounces to the list — listing will reflect current
    # state (or omit the agent), which is the user-facing truth.
    if not ok:
        _log.info("profile.agent_revoke.rejected", extra={"err": err})
    return RedirectResponse(url="/profile/agents", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/cards", response_class=HTMLResponse)
async def cards_search_page(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    q: Annotated[str, Query()] = "",
) -> Response:
    """Card search page — ILIKE against the Scryfall mirror."""
    needle = q.strip()
    results: list[Any] = []
    search_error = False
    if needle:
        try:
            results = await analytics_client.search_cards(
                settings.analytics_service_url, user.token, needle
            )
        except analytics_client.AnalyticsForbidden:
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        except analytics_client.AnalyticsClientError:
            _log.exception("analytics GET /cards call failed")
            search_error = True
    return templates.TemplateResponse(
        request,
        "cards.html",
        {
            "user": user,
            "q": needle,
            "submitted": bool(needle),
            "results": results,
            "search_error": search_error,
        },
    )


@app.get("/matches/{match_id}", response_class=HTMLResponse)
async def match_detail_page(
    match_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    try:
        match = await analytics_client.get_match_detail(
            settings.analytics_service_url, user.token, str(match_id)
        )
    except analytics_client.AnalyticsForbidden:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /matches/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if match is None:
        return Response(content="Match not found.", status_code=status.HTTP_404_NOT_FOUND)

    # Compute overall W/L/D from the games list.  Use hero_player_name
    # (resolved at parse time) to identify the uploading player.  Falls
    # back to players[0] only when the field is not available.
    overall_result = ""
    if match.players and match.games:
        hero = match.hero_player_name or match.players[0]
        user_wins = sum(1 for g in match.games if g.winner == hero)
        opp_wins = sum(1 for g in match.games if g.winner is not None and g.winner != hero)
        if user_wins > opp_wins:
            overall_result = "W"
        elif user_wins < opp_wins:
            overall_result = "L"
        elif user_wins or opp_wins:
            overall_result = "D"
    return templates.TemplateResponse(
        request,
        "match_detail.html",
        {
            "user": user,
            "match": match,
            "overall_result": overall_result,
            "review_status": match.review_status,
            "review_reason": match.review_reason,
            "format_options": [
                "Standard",
                "Pioneer",
                "Modern",
                "Legacy",
                "Vintage",
                "Pauper",
                "Commander",
                "Draft",
                "Sealed",
                "Historic",
                "Premodern",
                "Cube",
            ],
        },
    )


@app.get("/matches/{match_id}/games/{game_number}/turns", response_class=HTMLResponse)
async def match_game_turns(
    match_id: uuid.UUID,
    game_number: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """HTMX partial: per-game turn-by-turn state viewer."""
    try:
        turns_data = await analytics_client.get_game_turns(
            settings.analytics_service_url,
            user.token,
            str(match_id),
            game_number,
        )
    except analytics_client.AnalyticsForbidden:
        return HTMLResponse("<p>Session expired. Please reload the page.</p>", status_code=401)
    except analytics_client.AnalyticsClientError:
        _log.exception(
            "analytics GET /matches/%s/games/%s/turns call failed", match_id, game_number
        )
        return HTMLResponse(
            "<p>Turn data unavailable — analytics service could not be reached.</p>",
            status_code=503,
        )
    return templates.TemplateResponse(
        request,
        "_turn_viewer.html",
        {"turns_data": turns_data},
    )


@app.post("/matches/{match_id}/format")
async def match_set_format(
    match_id: uuid.UUID,
    request: Request,
    format: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    try:
        await analytics_client.update_match_format(
            settings.analytics_service_url,
            user.token,
            str(match_id),
            format,
        )
    except analytics_client.AnalyticsForbidden:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics PATCH format failed match_id=%s", match_id)
    return RedirectResponse(
        url=f"/matches/{match_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Metagame browser (F11)
# ---------------------------------------------------------------------------


@app.get("/metagame", response_class=HTMLResponse)
async def metagame_index(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Metagame landing — show format list, default to the most popular."""
    formats: list[dict[str, Any]] = []
    error: str | None = None
    try:
        formats = await analytics_client.get_metagame_formats(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /metagame/formats failed")
        error = "Analytics service unavailable."

    if formats and not error:
        # Redirect to the format with the most events
        top_format = formats[0].get("format", "")
        if top_format:
            return RedirectResponse(
                url=f"/metagame/{top_format}", status_code=status.HTTP_302_FOUND
            )

    return templates.TemplateResponse(
        request,
        "metagame.html",
        {
            "user": user,
            "formats": formats,
            "selected_format": None,
            "tiers": None,
            "events": [],
            "events_total": 0,
            "trends": None,
            "window": "30d",
            "error": error,
        },
    )


@app.get("/metagame/api/tiers/{format_name}", response_class=JSONResponse)
async def metagame_api_tiers(
    format_name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    window: Annotated[str, Query()] = "30d",
) -> Response:
    """JSON endpoint for Alpine.js dynamic tier fetching."""
    try:
        tiers = await analytics_client.get_metagame_tiers(
            settings.analytics_service_url, user.token, format_name, window
        )
    except analytics_client.AnalyticsForbidden:
        return JSONResponse({"error": "unauthorized"}, status_code=status.HTTP_401_UNAUTHORIZED)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /metagame/%s/tiers failed", format_name)
        return JSONResponse(
            {"error": "service_unavailable"}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )
    return JSONResponse(tiers)


@app.get("/metagame/api/trends/{format_name}", response_class=JSONResponse)
async def metagame_api_trends(
    format_name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    window: Annotated[str, Query()] = "30d",
) -> Response:
    """JSON endpoint for Chart.js trend data."""
    try:
        trends = await analytics_client.get_metagame_trends(
            settings.analytics_service_url, user.token, format_name, window
        )
    except analytics_client.AnalyticsForbidden:
        return JSONResponse({"error": "unauthorized"}, status_code=status.HTTP_401_UNAUTHORIZED)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /metagame/%s/trends failed", format_name)
        return JSONResponse(
            {"error": "service_unavailable"}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )
    return JSONResponse(trends)


@app.get("/metagame/{format_name}/events/{source}/{event_id}", response_class=HTMLResponse)
async def metagame_event_detail(
    format_name: str,
    source: str,
    event_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Single event detail page with decklists."""
    event: dict[str, Any] = {}
    error: str | None = None
    try:
        event = await analytics_client.get_metagame_event_detail(
            settings.analytics_service_url, user.token, format_name, source, event_id
        )
    except analytics_client.AnalyticsForbidden:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception(
            "analytics GET /metagame/%s/events/%s/%s failed",
            format_name,
            source,
            event_id,
        )
        error = "Analytics service unavailable."

    if not event and not error:
        return Response(content="Event not found.", status_code=status.HTTP_404_NOT_FOUND)

    return templates.TemplateResponse(
        request,
        "metagame_event.html",
        {
            "user": user,
            "format": format_name,
            "event": event,
            "error": error,
        },
    )


@app.get("/metagame/{format_name}", response_class=HTMLResponse)
async def metagame_format(
    format_name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    window: Annotated[str, Query()] = "30d",
) -> Response:
    """Format detail — tiers + events + trends."""
    formats: list[dict[str, Any]] = []
    tiers: dict[str, Any] | None = None
    events_data: dict[str, Any] = {}
    trends: dict[str, Any] | None = None
    error: str | None = None

    try:
        formats = await analytics_client.get_metagame_formats(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /metagame/formats failed")
        error = "Analytics service unavailable."

    if not error:
        try:
            tiers = await analytics_client.get_metagame_tiers(
                settings.analytics_service_url, user.token, format_name, window
            )
        except analytics_client.AnalyticsClientError:
            _log.exception("analytics GET /metagame/%s/tiers failed", format_name)

        try:
            events_data = await analytics_client.get_metagame_events(
                settings.analytics_service_url, user.token, format_name
            )
        except analytics_client.AnalyticsClientError:
            _log.exception("analytics GET /metagame/%s/events failed", format_name)

        try:
            trends = await analytics_client.get_metagame_trends(
                settings.analytics_service_url, user.token, format_name, window
            )
        except analytics_client.AnalyticsClientError:
            _log.exception("analytics GET /metagame/%s/trends failed", format_name)

    events_list = events_data.get("events", [])
    events_total = int(events_data.get("total", 0))

    return templates.TemplateResponse(
        request,
        "metagame.html",
        {
            "user": user,
            "formats": formats,
            "selected_format": format_name,
            "tiers": tiers,
            "events": events_list,
            "events_total": events_total,
            "trends": trends,
            "window": window,
            "error": error,
        },
    )


def _service_unavailable(
    request: Request,
    user: BrowserUser,
    template: str = "profile.html",
    extra_context: dict[str, Any] | None = None,
) -> Response:
    ctx: dict[str, Any] = {
        "user": user,
        "me": None,
        "error": "Authentication service unavailable. Please try again.",
    }
    if extra_context:
        ctx.update(extra_context)
    return templates.TemplateResponse(
        request,
        template,
        ctx,
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


# ---------------------------------------------------------------------------
# Admin panel — W3.5-C
# ---------------------------------------------------------------------------


_ADMIN_USERS_DEFAULT_PER_PAGE = 50
_ADMIN_USERS_MAX_PER_PAGE = 200


def _require_admin_or_403(request: Request, user: BrowserUser) -> Response | None:
    """Return a 403 response if `user` is not an admin, else None.

    Admin gating is enforced both here (cheap rejection for the common
    case) and at the auth service (authoritative). The double-check
    means a stale role claim or a rogue local edit can't slip through.
    """
    if user.role != "admin":
        return templates.TemplateResponse(
            request,
            "admin_forbidden.html",
            {"user": user},
            status_code=status.HTTP_403_FORBIDDEN,
        )
    return None


def _admin_forbidden(request: Request, user: BrowserUser) -> Response:
    """Render the admin-denied page.

    Used when auth's authoritative role/session check rejects the call
    even though the JWT claim said ``admin`` (revoked session, demoted
    role) — see :class:`auth_client.AuthForbidden`.
    """
    return templates.TemplateResponse(
        request,
        "admin_forbidden.html",
        {"user": user},
        status_code=status.HTTP_403_FORBIDDEN,
    )


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_list(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE),
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    offset = (page - 1) * per_page
    try:
        users, total = await auth_client.admin_list_users(
            settings.auth_service_url, user.token, limit=per_page, offset=offset
        )
    except auth_client.AuthForbidden:
        _log.info("admin.users.list.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/users call failed")
        return templates.TemplateResponse(
            request,
            "admin_users.html",
            {
                "user": user,
                "users": [],
                "total": 0,
                "page": page,
                "per_page": per_page,
                "error": "Authentication service unavailable. Please try again.",
                "result": None,
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {
            "user": user,
            "users": users,
            "total": total,
            "page": page,
            "per_page": per_page,
            "error": None,
            "result": None,
        },
    )


def _render_admin_users_sync(
    request: Request,
    user: BrowserUser,
    users: list[Any],
    total: int,
    *,
    page: int,
    per_page: int,
    error: str | None,
    result: dict[str, Any] | None,
    status_code: int,
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {
            "user": user,
            "users": users,
            "total": total,
            "page": page,
            "per_page": per_page,
            "error": error,
            "result": result,
        },
        status_code=status_code,
    )


async def _refetch_admin_users(
    settings: WebSettings,
    user: BrowserUser,
    *,
    page: int,
    per_page: int,
) -> tuple[list[Any], int]:
    """Best-effort list refetch for inline-error rendering paths.

    Swallows ``AuthForbidden`` and ``AuthClientError`` — by the time we
    call this, the original mutation has already produced a status the
    caller wants to surface; we just want list context underneath it.
    """
    try:
        return await auth_client.admin_list_users(
            settings.auth_service_url,
            user.token,
            limit=per_page,
            offset=(page - 1) * per_page,
        )
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        return [], 0


@app.post("/admin/users/{user_id}/delete")
async def admin_user_delete(
    user_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE),
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    if user_id == user.user_id:
        # Auth would also reject this, but short-circuit so we don't
        # waste a round trip — and so the inline error renders against
        # whatever list state the page already has.
        users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
        return _render_admin_users_sync(
            request,
            user,
            users,
            total,
            page=page,
            per_page=per_page,
            error="You cannot delete yourself.",
            result=None,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        ok, err = await auth_client.admin_delete_user(
            settings.auth_service_url, user.token, user_id
        )
    except auth_client.AuthForbidden:
        _log.info("admin.users.delete.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth DELETE /admin/users call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)

    # Fetch the list again so the inline error has context.
    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)

    if err == "cannot_delete_self":
        message = "You cannot delete yourself."
        code = status.HTTP_400_BAD_REQUEST
    elif err == "cannot_delete_last_admin":
        message = "Cannot delete the last admin account."
        code = status.HTTP_400_BAD_REQUEST
    elif err == "user_not_found":
        message = "That user no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not delete user."
        code = status.HTTP_400_BAD_REQUEST

    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error=message,
        result=None,
        status_code=code,
    )


@app.post("/admin/users/{user_id}/reset-password")
async def admin_user_reset_password(
    user_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE),
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        reset, err = await auth_client.admin_reset_password(
            settings.auth_service_url, user.token, user_id
        )
    except auth_client.AuthForbidden:
        _log.info("admin.users.reset.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/users reset-password call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)

    if reset is not None:
        temp, revoked = reset
        result = {
            "user_id": user_id,
            "temporary_password": temp,
            "revoked_sessions": revoked,
        }
        return _render_admin_users_sync(
            request,
            user,
            users,
            total,
            page=page,
            per_page=per_page,
            error=None,
            result=result,
            status_code=200,
        )

    if err == "user_not_found":
        return _render_admin_users_sync(
            request,
            user,
            users,
            total,
            page=page,
            per_page=per_page,
            error="That user no longer exists.",
            result=None,
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error="Could not reset password.",
        result=None,
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@app.post("/admin/users/create")
async def admin_user_create(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()] = "user",
    must_change_password: Annotated[str, Form()] = "",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE)
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    se, sp = email.strip(), password.strip()
    if not se or not sp:
        users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
        return _render_admin_users_sync(
            request,
            user,
            users,
            total,
            page=page,
            per_page=per_page,
            error="Email and password are required.",
            result=None,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        cu, err = await auth_client.admin_create_user(
            settings.auth_service_url,
            user.token,
            email=se,
            password=sp,
            role=role if role in ("user", "admin") else "user",
            must_change_password=bool(must_change_password),
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        return Response(
            content="Authentication service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if cu is not None:
        return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)
    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
    msg = (
        "A user with that email already exists."
        if err == "email_already_exists"
        else "Could not create user."
    )
    sc = status.HTTP_409_CONFLICT if err == "email_already_exists" else status.HTTP_400_BAD_REQUEST
    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error=msg,
        result=None,
        status_code=sc,
    )


@app.post("/admin/users/{user_id}/toggle-role")
async def admin_user_toggle_role(
    user_id: int,
    request: Request,
    new_role: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE)
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if new_role not in ("user", "admin"):
        return RedirectResponse(
            url=f"/admin/users?page={page}&per_page={per_page}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        updated, err = await auth_client.admin_update_user(
            settings.auth_service_url, user.token, user_id, role=new_role
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        return Response(
            content="Authentication service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if updated is not None:
        return RedirectResponse(
            url=f"/admin/users?page={page}&per_page={per_page}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
    if err == "user_not_found":
        msg, sc = "That user no longer exists.", status.HTTP_404_NOT_FOUND
    elif err == "cannot_demote_last_admin":
        msg, sc = "Cannot demote the last admin.", status.HTTP_400_BAD_REQUEST
    else:
        msg, sc = "Could not update role.", status.HTTP_400_BAD_REQUEST
    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error=msg,
        result=None,
        status_code=sc,
    )


@app.post("/admin/users/{user_id}/toggle-disabled")
async def admin_user_toggle_disabled(
    user_id: int,
    request: Request,
    disabled: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE)
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        updated, err = await auth_client.admin_update_user(
            settings.auth_service_url, user.token, user_id, disabled=(disabled == "true")
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        return Response(
            content="Authentication service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if updated is not None:
        return RedirectResponse(
            url=f"/admin/users?page={page}&per_page={per_page}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
    if err == "user_not_found":
        msg, sc = "That user no longer exists.", status.HTTP_404_NOT_FOUND
    elif err == "cannot_disable_self":
        msg, sc = "You cannot disable yourself.", status.HTTP_400_BAD_REQUEST
    else:
        msg, sc = "Could not update user.", status.HTTP_400_BAD_REQUEST
    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error=msg,
        result=None,
        status_code=sc,
    )


@app.post("/admin/users/{user_id}/revoke-sessions")
async def admin_user_revoke_sessions(
    user_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE)
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        count, err = await auth_client.admin_revoke_user_sessions(
            settings.auth_service_url, user.token, user_id
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        return Response(
            content="Authentication service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
    if count is not None:
        return _render_admin_users_sync(
            request,
            user,
            users,
            total,
            page=page,
            per_page=per_page,
            error=None,
            result={"revoke_sessions": True, "user_id": user_id, "revoked_count": count},
            status_code=200,
        )
    if err == "user_not_found":
        msg, sc = "That user no longer exists.", status.HTTP_404_NOT_FOUND
    else:
        msg, sc = "Could not revoke sessions.", status.HTTP_400_BAD_REQUEST
    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error=msg,
        result=None,
        status_code=sc,
    )


@app.post("/admin/users/{user_id}/reparse")
async def admin_user_reparse(
    user_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE)
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    """Admin: reparse all of a specific user's matches.

    Equivalent to looping over every agent the user owns and calling
    per-agent reparse, but done as a single delete in parser.matches
    filtered by user_id. The parser's backfill scanner re-processes
    from ingest.game_log_files on the next cycle.
    """
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        result = await parser_client.admin_delete_user_matches(
            settings.parser_service_url, user.token, user_id
        )
    except parser_client.ParserForbidden:
        _log.info("admin.users.reparse.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except parser_client.ParserClientError:
        _log.exception("parser DELETE /parser/admin/matches/%s call failed", user_id)
        return Response(
            content="Parser service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    users, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
    return _render_admin_users_sync(
        request,
        user,
        users,
        total,
        page=page,
        per_page=per_page,
        error=None,
        result={"reparse": True, "user_id": user_id, "deleted_count": result.deleted_count},
        status_code=200,
    )


# ---------------------------------------------------------------------------
# Admin agents — W3.6.2 (cross-user view + revoke-any)
# ---------------------------------------------------------------------------


_ADMIN_AGENTS_DEFAULT_PER_PAGE = 50
_ADMIN_AGENTS_MAX_PER_PAGE = 200


async def _refetch_admin_agents(
    settings: WebSettings,
    user: BrowserUser,
    *,
    page: int,
    per_page: int,
) -> tuple[list[Any], int]:
    """Best-effort agents list refetch for inline-error rendering.

    Mirrors :func:`_refetch_admin_users`: swallows AuthForbidden /
    AuthClientError so the caller can surface the original mutation
    status against a (possibly empty) list view.
    """
    try:
        return await auth_client.admin_list_agents(
            settings.auth_service_url,
            user.token,
            limit=per_page,
            offset=(page - 1) * per_page,
        )
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        return [], 0


def _render_admin_agents_sync(
    request: Request,
    user: BrowserUser,
    agents: list[Any],
    total: int,
    *,
    page: int,
    per_page: int,
    error: str | None,
    status_code: int,
    rotated_key: dict[str, Any] | None = None,
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin_agents.html",
        {
            "user": user,
            "agents": agents,
            "total": total,
            "page": page,
            "per_page": per_page,
            "error": error,
            "rotated_key": rotated_key,
        },
        status_code=status_code,
    )


@app.get("/admin/agents", response_class=HTMLResponse)
async def admin_agents_list(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE),
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    offset = (page - 1) * per_page
    try:
        agents, total = await auth_client.admin_list_agents(
            settings.auth_service_url, user.token, limit=per_page, offset=offset
        )
    except auth_client.AuthForbidden:
        _log.info("admin.agents.list.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/agents call failed")
        return _render_admin_agents_sync(
            request,
            user,
            [],
            0,
            page=page,
            per_page=per_page,
            error="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error=None,
        status_code=200,
    )


@app.post("/admin/agents/{agent_id}/reparse")
async def admin_agent_reparse(
    agent_id: uuid.UUID,
    request: Request,
    user_id: Annotated[int, Query(ge=1)],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE),
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    """Admin: force reparse for a specific agent."""
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        result = await parser_client.admin_delete_user_matches(
            settings.parser_service_url, user.token, user_id, agent_id=str(agent_id)
        )
    except parser_client.ParserForbidden:
        _log.info("admin.agents.reparse.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except parser_client.ParserClientError:
        _log.exception(
            "parser DELETE /parser/admin/matches/%s?agent_id=%s call failed",
            user_id,
            agent_id,
        )
        return Response(
            content="Parser service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    return templates.TemplateResponse(
        request,
        "admin_agents.html",
        {
            "user": user,
            "agents": agents,
            "total": total,
            "page": page,
            "per_page": per_page,
            "error": None,
            "reparse_result": result,
        },
    )


@app.post("/admin/agents/{agent_id}/revoke")
async def admin_agent_revoke(
    # Typed UUID rejects malformed IDs at the route boundary with 422
    # so they never round-trip and surface as a misclassified 503.
    agent_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE),
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        ok, err = await auth_client.admin_revoke_agent(
            settings.auth_service_url, user.token, str(agent_id)
        )
    except auth_client.AuthForbidden:
        _log.info("admin.agents.revoke.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/agents revoke call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        return RedirectResponse(
            url=f"/admin/agents?page={page}&per_page={per_page}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # 404 — agent gone in the meantime. Surface inline so the operator
    # sees the page they expected, with a note that the row is stale.
    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    if err == "agent_not_found":
        message = "That agent no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not revoke agent."
        code = status.HTTP_400_BAD_REQUEST
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error=message,
        status_code=code,
    )


@app.post("/admin/agents/{agent_id}/rotate-key")
async def admin_agent_rotate_key(
    agent_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE),
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        result, err = await auth_client.admin_rotate_agent_key(
            settings.auth_service_url, user.token, str(agent_id)
        )
    except auth_client.AuthForbidden:
        _log.info("admin.agents.rotate_key.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/agents rotate-key call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    if result is not None:
        return _render_admin_agents_sync(
            request,
            user,
            agents,
            total,
            page=page,
            per_page=per_page,
            error=None,
            status_code=200,
            rotated_key={"agent_id": str(agent_id), "api_token": result.api_token},
        )

    if err == "agent_not_found":
        message = "That agent no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not rotate key."
        code = status.HTTP_400_BAD_REQUEST
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error=message,
        status_code=code,
    )


@app.post("/admin/agents/{agent_id}/delete")
async def admin_agent_delete(
    agent_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE),
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        ok, err = await auth_client.admin_delete_agent(
            settings.auth_service_url, user.token, str(agent_id)
        )
    except auth_client.AuthForbidden:
        _log.info("admin.agents.delete.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth DELETE /admin/agents call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        return RedirectResponse(
            url=f"/admin/agents?page={page}&per_page={per_page}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    if err == "agent_not_found":
        message = "That agent no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not delete agent."
        code = status.HTTP_400_BAD_REQUEST
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error=message,
        status_code=code,
    )


@app.post("/admin/agents/reparse-all")
async def admin_agents_reparse_all(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE)
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        result = await parser_client.admin_delete_all_matches(
            settings.parser_service_url, user.token
        )
    except parser_client.ParserForbidden:
        return _admin_forbidden(request, user)
    except parser_client.ParserClientError:
        return Response(
            content="Parser service unavailable.", status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        )
    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    return templates.TemplateResponse(
        request,
        "admin_agents.html",
        {
            "user": user,
            "agents": agents,
            "total": total,
            "page": page,
            "per_page": per_page,
            "error": None,
            "reparse_result": result,
        },
    )


@app.post("/admin/agents/cleanup-stale")
async def admin_agents_cleanup_stale(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE)
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        count, err = await auth_client.admin_cleanup_stale_agents(
            settings.auth_service_url, user.token
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        return Response(
            content="Authentication service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    if count is not None:
        return templates.TemplateResponse(
            request,
            "admin_agents.html",
            {
                "user": user,
                "agents": agents,
                "total": total,
                "page": page,
                "per_page": per_page,
                "error": None,
                "cleanup_result": {"revoked_count": count},
            },
        )
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error="Could not clean up stale agents.",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


# ---------------------------------------------------------------------------
# Admin reingest — agent file re-upload via heartbeat signal
# ---------------------------------------------------------------------------


@app.post("/admin/agents/{agent_id}/reingest")
async def admin_agent_reingest(
    agent_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE)
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    """Admin: request reingest for a specific agent."""
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        count, err = await auth_client.admin_reingest_agent(
            settings.auth_service_url, user.token, str(agent_id)
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth POST reingest-agent call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    if err is None:
        return templates.TemplateResponse(
            request,
            "admin_agents.html",
            {
                "user": user,
                "agents": agents,
                "total": total,
                "page": page,
                "per_page": per_page,
                "error": None,
                "reingest_result": {"affected_count": count},
            },
        )
    if err == "agent_not_found":
        message = "That agent no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not request reingest."
        code = status.HTTP_400_BAD_REQUEST
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error=message,
        status_code=code,
    )


@app.post("/admin/users/{user_id}/reingest")
async def admin_user_reingest(
    user_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_USERS_MAX_PER_PAGE)
    ] = _ADMIN_USERS_DEFAULT_PER_PAGE,
) -> Response:
    """Admin: request reingest for all of a user's agents."""
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        count, err = await auth_client.admin_reingest_user_agents(
            settings.auth_service_url, user.token, user_id
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth POST reingest-user call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    users_list, total = await _refetch_admin_users(settings, user, page=page, per_page=per_page)
    if err is None:
        return _render_admin_users_sync(
            request,
            user,
            users_list,
            total,
            page=page,
            per_page=per_page,
            error=None,
            result={"reingest": True, "user_id": user_id, "affected_count": count},
            status_code=200,
        )
    if err == "user_not_found":
        message = "That user no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not request reingest."
        code = status.HTTP_400_BAD_REQUEST
    return _render_admin_users_sync(
        request,
        user,
        users_list,
        total,
        page=page,
        per_page=per_page,
        error=message,
        result=None,
        status_code=code,
    )


@app.post("/admin/agents/reingest-all")
async def admin_agents_reingest_all(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE)
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    """Admin: request reingest for all active agents globally."""
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        count, err = await auth_client.admin_reingest_all_agents(
            settings.auth_service_url, user.token
        )
    except auth_client.AuthForbidden:
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth POST reingest-all call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    agents, total = await _refetch_admin_agents(settings, user, page=page, per_page=per_page)
    if err is None:
        return templates.TemplateResponse(
            request,
            "admin_agents.html",
            {
                "user": user,
                "agents": agents,
                "total": total,
                "page": page,
                "per_page": per_page,
                "error": None,
                "reingest_result": {"affected_count": count},
            },
        )
    return _render_admin_agents_sync(
        request,
        user,
        agents,
        total,
        page=page,
        per_page=per_page,
        error="Could not request reingest for all agents.",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


# ---------------------------------------------------------------------------
# Admin settings — W3.6.3 (registration mode toggle, UID=1 only)
# ---------------------------------------------------------------------------


# Mirrors auth-side ``ROOT_ADMIN_USER_ID`` — the original installer
# admin (auto-PK 1, minted by ``bootstrap_admin``). The web layer
# checks this purely for UI state (enabled vs. disabled toggle); the
# auth service is the authoritative gate on writes.
_ROOT_ADMIN_USER_ID = 1
_REGISTRATION_MODE_LOCK_TOOLTIP = (
    "Registration mode is locked to UID=1 (the original installer admin)."
)


def _render_admin_settings(
    request: Request,
    user: BrowserUser,
    *,
    mode: auth_client.RegistrationMode | None,
    tunables: auth_client.TunablesResult | None = None,
    cards_status: dict[str, Any] | None = None,
    scraper_health: dict[str, Any] | None = None,
    scraper_healths: list[dict[str, Any]] | None = None,
    admin_motd: auth_client.MotdResult | None = None,
    motd_saved: bool = False,
    motd_cleared: bool = False,
    motd_error: str | None = None,
    error: str | None,
    saved: bool,
    tunables_saved: bool = False,
    tunables_error: str | None = None,
    scrape_mtgo_triggered: bool = False,
    scrape_mtgtop8_triggered: bool = False,
    scrape_mtgo_running: bool = False,
    scrape_mtgtop8_running: bool = False,
    status_code: int,
) -> Response:
    # Build per-scraper dicts for template convenience
    mtgo_health: dict[str, Any] | None = scraper_health  # backward compat
    mtgtop8_health: dict[str, Any] | None = None
    if scraper_healths:
        for sh in scraper_healths:
            if sh.get("scraper_name") == "mtgo":
                mtgo_health = sh
            elif sh.get("scraper_name") == "mtgtop8":
                mtgtop8_health = sh
    return templates.TemplateResponse(
        request,
        "admin_settings.html",
        {
            "user": user,
            "mode": mode,
            "tunables": tunables,
            "cards_status": cards_status,
            "scraper_health": mtgo_health,
            "mtgtop8_health": mtgtop8_health,
            "admin_motd": admin_motd,
            "motd_saved": motd_saved,
            "motd_cleared": motd_cleared,
            "motd_error": motd_error,
            "is_root_admin": user.user_id == _ROOT_ADMIN_USER_ID,
            "lock_tooltip": _REGISTRATION_MODE_LOCK_TOOLTIP,
            "error": error,
            "saved": saved,
            "tunables_saved": tunables_saved,
            "tunables_error": tunables_error,
            "scrape_mtgo_triggered": scrape_mtgo_triggered,
            "scrape_mtgtop8_triggered": scrape_mtgtop8_triggered,
            "scrape_mtgo_running": scrape_mtgo_running,
            "scrape_mtgtop8_running": scrape_mtgtop8_running,
        },
        status_code=status_code,
    )


@app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    saved: Annotated[int, Query(ge=0, le=1)] = 0,
    tunables_saved: Annotated[int, Query(ge=0, le=1)] = 0,
    motd_saved: Annotated[int, Query(ge=0, le=1)] = 0,
    motd_cleared: Annotated[int, Query(ge=0, le=1)] = 0,
    scrape_mtgo_triggered: Annotated[int, Query(ge=0, le=1)] = 0,
    scrape_mtgtop8_triggered: Annotated[int, Query(ge=0, le=1)] = 0,
    scrape_mtgo_running: Annotated[int, Query(ge=0, le=1)] = 0,
    scrape_mtgtop8_running: Annotated[int, Query(ge=0, le=1)] = 0,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    mode: auth_client.RegistrationMode | None = None
    tunables: auth_client.TunablesResult | None = None
    admin_motd: auth_client.MotdResult | None = None
    cards_status: dict[str, Any] | None = None
    scraper_healths: list[dict[str, Any]] | None = None
    error: str | None = None

    try:
        mode = await auth_client.admin_get_registration_mode(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("admin.settings.get.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/settings/registration-mode call failed")
        error = "Authentication service unavailable. Please try again."

    try:
        tunables = await auth_client.admin_get_tunables(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("admin.settings.tunables.get.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/settings/tunables call failed")
        if error is None:
            error = "Authentication service unavailable. Please try again."

    try:
        admin_motd = await auth_client.admin_get_motd(settings.auth_service_url, user.token)
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        _log.debug("admin.settings.motd unavailable")

    try:
        cards_status = await analytics_client.admin_get_cards_status(
            settings.analytics_service_url, user.token
        )
    except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
        _log.debug("admin.settings.cards_status unavailable")
    try:
        scraper_healths = await analytics_client.admin_get_all_scraper_health(
            settings.analytics_service_url, user.token
        )
    except (analytics_client.AnalyticsForbidden, analytics_client.AnalyticsClientError):
        _log.debug("admin.settings.scraper_health unavailable")
    code = (
        status.HTTP_503_SERVICE_UNAVAILABLE if error and mode is None and tunables is None else 200
    )
    return _render_admin_settings(
        request,
        user,
        mode=mode,
        tunables=tunables,
        admin_motd=admin_motd,
        cards_status=cards_status,
        scraper_healths=scraper_healths,
        error=error,
        saved=saved == 1,
        tunables_saved=tunables_saved == 1,
        motd_saved=motd_saved == 1,
        motd_cleared=motd_cleared == 1,
        scrape_mtgo_triggered=scrape_mtgo_triggered == 1,
        scrape_mtgtop8_triggered=scrape_mtgtop8_triggered == 1,
        scrape_mtgo_running=scrape_mtgo_running == 1,
        scrape_mtgtop8_running=scrape_mtgtop8_running == 1,
        status_code=code,
    )


@app.post("/admin/settings/registration-mode")
async def admin_settings_registration_mode(
    request: Request,
    mode: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    # Browsers can't form-PUT, so this route is the form handler that
    # forwards to auth's PUT endpoint. Auth is the authoritative gate
    # on UID=1 — we don't short-circuit here so a non-root admin who
    # bypasses the disabled UI still gets a clean inline error.
    try:
        view, err = await auth_client.admin_set_registration_mode(
            settings.auth_service_url, user.token, mode
        )
    except auth_client.AuthForbidden:
        _log.info("admin.settings.put.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth PUT /admin/settings/registration-mode call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if view is not None:
        # 303 so the browser does a GET on the success page (refresh-
        # safe). Re-fetching through the GET handler keeps the UI in
        # sync with whatever auth has now committed.
        return RedirectResponse(
            url="/admin/settings?saved=1", status_code=status.HTTP_303_SEE_OTHER
        )

    # Inline error: re-fetch current mode so the page still shows the
    # active value alongside the failure message.
    current: auth_client.RegistrationMode | None
    try:
        current = await auth_client.admin_get_registration_mode(
            settings.auth_service_url, user.token
        )
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        current = None

    if err == "not_root_admin":
        message = _REGISTRATION_MODE_LOCK_TOOLTIP
        code = status.HTTP_403_FORBIDDEN
    elif err == "invalid_mode":
        message = "Invalid registration mode."
        code = status.HTTP_400_BAD_REQUEST
    else:
        message = "Could not update registration mode."
        code = status.HTTP_400_BAD_REQUEST

    return _render_admin_settings(
        request,
        user,
        mode=current,
        error=message,
        saved=False,
        status_code=code,
    )


@app.post("/admin/settings/tunables")
async def admin_settings_tunables(
    request: Request,
    backfill_batch_size: Annotated[int, Form()],
    backfill_interval_seconds: Annotated[int, Form()],
    scryfall_sync_interval_days: Annotated[int, Form()],
    mtgo_scraper_interval_hours: Annotated[int, Form()],
    parser_version: Annotated[str, Form()],
    reparse_min_version: Annotated[str, Form()],
    min_agent_version: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    updates: dict[str, int | str] = {
        "backfill_batch_size": backfill_batch_size,
        "backfill_interval_seconds": backfill_interval_seconds,
        "scryfall_sync_interval_days": scryfall_sync_interval_days,
        "mtgo_scraper_interval_hours": mtgo_scraper_interval_hours,
        "parser_version": parser_version,
        "reparse_min_version": reparse_min_version,
        "min_agent_version": min_agent_version,
    }

    try:
        result, err = await auth_client.admin_update_tunables(
            settings.auth_service_url, user.token, updates
        )
    except auth_client.AuthForbidden:
        _log.info("admin.settings.tunables.put.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth PATCH /admin/settings/tunables call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if result is not None:
        return RedirectResponse(
            url="/admin/settings?tunables_saved=1", status_code=status.HTTP_303_SEE_OTHER
        )

    # Inline error — re-fetch state for the page.  Best-effort:
    # swallowing here is correct because the original mutation error is
    # what we want to surface; list context underneath is nice-to-have.
    mode: auth_client.RegistrationMode | None = None
    tunables: auth_client.TunablesResult | None = None
    with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
        mode = await auth_client.admin_get_registration_mode(settings.auth_service_url, user.token)
    with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
        tunables = await auth_client.admin_get_tunables(settings.auth_service_url, user.token)

    return _render_admin_settings(
        request,
        user,
        mode=mode,
        tunables=tunables,
        error=None,
        saved=False,
        tunables_error="Invalid tunable values. Check ranges and try again.",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@app.post("/admin/settings/motd")
async def admin_settings_set_motd(
    request: Request,
    motd_message: Annotated[str, Form()],
    motd_severity: Annotated[str, Form()],
    motd_expires_at: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    message = motd_message.strip()
    severity = motd_severity.strip()
    expires_at_raw = motd_expires_at.strip()

    if not message:
        admin_motd_err: auth_client.MotdResult | None = None
        with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
            admin_motd_err = await auth_client.admin_get_motd(settings.auth_service_url, user.token)
        mode_err: auth_client.RegistrationMode | None = None
        with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
            mode_err = await auth_client.admin_get_registration_mode(
                settings.auth_service_url, user.token
            )
        return _render_admin_settings(
            request,
            user,
            mode=mode_err,
            admin_motd=admin_motd_err,
            error=None,
            saved=False,
            motd_error="Banner message is required.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if severity not in ("info", "warning"):
        severity = "info"

    if (
        expires_at_raw
        and "T" in expires_at_raw
        and "+" not in expires_at_raw
        and "Z" not in expires_at_raw
    ):
        expires_at_iso = expires_at_raw + ":00+00:00"
    else:
        expires_at_iso = expires_at_raw

    try:
        result, err = await auth_client.admin_set_motd(
            settings.auth_service_url,
            user.token,
            message=message,
            severity=severity,
            expires_at=expires_at_iso,
        )
    except auth_client.AuthForbidden:
        _log.info("admin.settings.motd.set.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth PUT /admin/settings/motd call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if result is not None:
        _reset_motd_cache()
        return RedirectResponse(
            url="/admin/settings?motd_saved=1", status_code=status.HTTP_303_SEE_OTHER
        )

    admin_motd_re: auth_client.MotdResult | None = None
    with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
        admin_motd_re = await auth_client.admin_get_motd(settings.auth_service_url, user.token)
    mode_re: auth_client.RegistrationMode | None = None
    with contextlib.suppress(auth_client.AuthForbidden, auth_client.AuthClientError):
        mode_re = await auth_client.admin_get_registration_mode(
            settings.auth_service_url, user.token
        )
    return _render_admin_settings(
        request,
        user,
        mode=mode_re,
        admin_motd=admin_motd_re,
        error=None,
        saved=False,
        motd_error="Could not set the banner. Check the expiration date.",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@app.post("/admin/settings/motd/clear")
async def admin_settings_clear_motd(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        await auth_client.admin_clear_motd(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("admin.settings.motd.clear.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth DELETE /admin/settings/motd call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    _reset_motd_cache()
    return RedirectResponse(
        url="/admin/settings?motd_cleared=1", status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/settings/scrape-mtgo")
async def admin_settings_scrape_mtgo(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        await analytics_client.admin_trigger_mtgo_scrape(settings.analytics_service_url, user.token)
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsConflict:
        # A run is already in progress. Say so instead of pretending the
        # click started something.
        return RedirectResponse(
            url="/admin/settings?scrape_mtgo_running=1", status_code=status.HTTP_303_SEE_OTHER
        )
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /admin/scrape-mtgo call failed")
        return Response(
            content="Analytics service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return RedirectResponse(
        url="/admin/settings?scrape_mtgo_triggered=1", status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/settings/scrape-mtgtop8")
async def admin_settings_scrape_mtgtop8(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        await analytics_client.admin_trigger_mtgtop8_scrape(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsConflict:
        # A run is already in progress. Say so instead of pretending the
        # click started something.
        return RedirectResponse(
            url="/admin/settings?scrape_mtgtop8_running=1", status_code=status.HTTP_303_SEE_OTHER
        )
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /admin/scrape-mtgtop8 call failed")
        return Response(
            content="Analytics service unavailable.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return RedirectResponse(
        url="/admin/settings?scrape_mtgtop8_triggered=1",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Admin scrapers dashboard (F13)
# ---------------------------------------------------------------------------

_VALID_SCRAPER_NAMES = {"mtgo", "mtgtop8"}


@app.get("/admin/scrapers", response_class=HTMLResponse)
async def admin_scrapers_dashboard(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    scrapers: list[dict[str, Any]] = []
    # The trigger/toggle/interval/reset handlers all redirect back here
    # with ?error=..., so read it: without this the "already running"
    # answer to a duplicate trigger would never reach the admin.
    error: str | None = request.query_params.get("error")
    success_msg: str | None = request.query_params.get("success")
    try:
        scrapers = await analytics_client.admin_get_scrapers(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /admin/scrapers failed")
        error = "Analytics service unavailable."
    return templates.TemplateResponse(
        request,
        "admin_scrapers.html",
        {
            "user": user,
            "scrapers": scrapers,
            "error": error,
            "success": success_msg,
        },
    )


@app.post("/admin/scrapers/{name}/toggle")
async def admin_scraper_toggle(
    name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if name not in _VALID_SCRAPER_NAMES:
        return Response(content="Unknown scraper.", status_code=status.HTTP_404_NOT_FOUND)
    try:
        # Fetch current state then toggle
        scrapers = await analytics_client.admin_get_scrapers(
            settings.analytics_service_url, user.token
        )
        current_enabled = True
        for s in scrapers:
            if s.get("scraper_name") == name:
                current_enabled = s.get("enabled", True)
                break
        await analytics_client.admin_update_scraper(
            settings.analytics_service_url,
            user.token,
            name,
            enabled=not current_enabled,
        )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics PATCH /admin/scrapers/%s toggle failed", name)
        return RedirectResponse(
            url="/admin/scrapers?error=Toggle+failed",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    action = "disabled" if current_enabled else "enabled"
    return RedirectResponse(
        url=f"/admin/scrapers?success={name}+{action}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/scrapers/{name}/interval")
async def admin_scraper_interval(
    name: str,
    request: Request,
    interval_hours: Annotated[int, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if name not in _VALID_SCRAPER_NAMES:
        return Response(content="Unknown scraper.", status_code=status.HTTP_404_NOT_FOUND)
    clamped = max(1, min(168, interval_hours))
    try:
        await analytics_client.admin_update_scraper(
            settings.analytics_service_url,
            user.token,
            name,
            interval_hours=clamped,
        )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics PATCH /admin/scrapers/%s interval failed", name)
        return RedirectResponse(
            url="/admin/scrapers?error=Interval+update+failed",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/admin/scrapers?success={name}+interval+set+to+{clamped}h",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/scrapers/{name}/trigger")
async def admin_scraper_trigger(
    name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if name not in _VALID_SCRAPER_NAMES:
        return Response(content="Unknown scraper.", status_code=status.HTTP_404_NOT_FOUND)
    try:
        if name == "mtgo":
            await analytics_client.admin_trigger_mtgo_scrape(
                settings.analytics_service_url, user.token
            )
        elif name == "mtgtop8":
            await analytics_client.admin_trigger_mtgtop8_scrape(
                settings.analytics_service_url, user.token
            )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsConflict:
        return RedirectResponse(
            url=f"/admin/scrapers?error={name}+scrape+already+running",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /admin/scrape-%s trigger failed", name)
        return RedirectResponse(
            url="/admin/scrapers?error=Trigger+failed",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/admin/scrapers?success={name}+scrape+triggered",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/scrapers/{name}/reset")
async def admin_scraper_reset(
    name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if name not in _VALID_SCRAPER_NAMES:
        return Response(content="Unknown scraper.", status_code=status.HTTP_404_NOT_FOUND)
    try:
        await analytics_client.admin_reset_scraper_health(
            settings.analytics_service_url, user.token, name
        )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /admin/scraper-health/reset failed for %s", name)
        return RedirectResponse(
            url="/admin/scrapers?error=Reset+failed",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/admin/scrapers?success={name}+health+reset",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/admin/scrapers/{name}/events", response_class=HTMLResponse)
async def admin_scraper_events_page(
    name: str,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=100)] = 20,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if name not in _VALID_SCRAPER_NAMES:
        return Response(content="Unknown scraper.", status_code=status.HTTP_404_NOT_FOUND)
    events: list[dict[str, Any]] = []
    total = 0
    error: str | None = None
    try:
        data = await analytics_client.admin_get_scraper_events(
            settings.analytics_service_url, user.token, name, page, per_page
        )
        events = data.get("events", [])
        total = int(data.get("total", 0))
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /admin/scrapers/%s/events failed", name)
        error = "Analytics service unavailable."
    return templates.TemplateResponse(
        request,
        "admin_scraper_events.html",
        {
            "user": user,
            "scraper_name": name,
            "events": events,
            "total": total,
            "page": page,
            "per_page": per_page,
            "event_detail": None,
            "error": error,
        },
    )


@app.get("/admin/scrapers/{name}/events/{event_id}", response_class=HTMLResponse)
async def admin_scraper_event_detail_page(
    name: str,
    event_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if name not in _VALID_SCRAPER_NAMES:
        return Response(content="Unknown scraper.", status_code=status.HTTP_404_NOT_FOUND)
    detail: dict[str, Any] = {}
    error: str | None = None
    try:
        detail = await analytics_client.admin_get_scraper_event_detail(
            settings.analytics_service_url, user.token, name, event_id
        )
    except analytics_client.AnalyticsForbidden:
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /admin/scrapers/%s/events/%s failed", name, event_id)
        error = "Analytics service unavailable."
    if not detail and not error:
        return Response(content="Event not found.", status_code=status.HTTP_404_NOT_FOUND)
    return templates.TemplateResponse(
        request,
        "admin_scraper_events.html",
        {
            "user": user,
            "scraper_name": name,
            "events": [],
            "total": 0,
            "page": 1,
            "per_page": 20,
            "event_detail": detail,
            "error": error,
        },
    )


# ---------------------------------------------------------------------------
# Admin invites — W3.6.4 (admin mints invite tokens)
# ---------------------------------------------------------------------------


_ADMIN_INVITES_DEFAULT_PER_PAGE = 50
_ADMIN_INVITES_MAX_PER_PAGE = 200
_INVITE_DEFAULT_EXPIRES_HOURS = 168  # 7 days
_INVITE_MAX_EXPIRES_HOURS = 720  # 30 days — mirrors auth-side cap


def _format_age(created_at: Any) -> str | None:
    """Human-friendly age for the invite list.

    Renders as "Nh" under a day, "Nd" otherwise — enough resolution for
    the admin to spot stale invites without flooding the UI with
    seconds. Returns None when the timestamp couldn't be parsed
    upstream so the template can fall back to "—".
    """
    if created_at is None:
        return None
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    delta = _dt.now(_UTC) - created_at
    hours = int(delta.total_seconds() // 3600)
    if hours < 24:
        return f"{hours}h"
    return f"{hours // 24}d"


def _invite_url(request: Request, token: str) -> str:
    """Build the user-facing invite URL with the plaintext token.

    Uses the request's scheme + host so dev (http://localhost:8000) and
    prod (https://da.example.com) both produce a working link without
    config plumbing.
    """
    base = str(request.base_url).rstrip("/")
    return f"{base}/register?token={token}"


def _render_admin_invites(
    request: Request,
    user: BrowserUser,
    *,
    invites: list[Any],
    total: int,
    page: int,
    per_page: int,
    error: str | None,
    created: dict[str, Any] | None,
    status_code: int,
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin_invites.html",
        {
            "user": user,
            "invites": invites,
            "total": total,
            "page": page,
            "per_page": per_page,
            "error": error,
            "created": created,
            "default_hours": _INVITE_DEFAULT_EXPIRES_HOURS,
            "max_hours": _INVITE_MAX_EXPIRES_HOURS,
        },
        status_code=status_code,
    )


def _decorate_invites(items: list[Any]) -> list[Any]:
    decorated: list[Any] = []
    for item in items:
        item.age = _format_age(item.created_at)
        decorated.append(item)
    return decorated


async def _refetch_admin_invites(
    settings: WebSettings,
    user: BrowserUser,
    *,
    page: int,
    per_page: int,
) -> tuple[list[Any], int]:
    """Best-effort list refetch for inline-error rendering paths.

    Mirrors ``_refetch_admin_users``: by the time we call this, the
    original mutation already produced the status the caller wants to
    surface, so swallowing is correct here. The primary GET handler
    must not use this helper — it needs to propagate auth/service
    errors so '503 unavailable' doesn't render as 'no invites'.
    """
    try:
        items, total = await auth_client.admin_list_invites(
            settings.auth_service_url, user.token, page=page, per_page=per_page
        )
    except (auth_client.AuthForbidden, auth_client.AuthClientError):
        return [], 0
    return _decorate_invites(items), total


@app.get("/admin/invites", response_class=HTMLResponse)
async def admin_invites_list(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_INVITES_MAX_PER_PAGE),
    ] = _ADMIN_INVITES_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        items, total = await auth_client.admin_list_invites(
            settings.auth_service_url, user.token, page=page, per_page=per_page
        )
    except auth_client.AuthForbidden:
        _log.info("admin.invites.list.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth GET /admin/invites call failed")
        return _render_admin_invites(
            request,
            user,
            invites=[],
            total=0,
            page=page,
            per_page=per_page,
            error="Authentication service unavailable. Please try again.",
            created=None,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _render_admin_invites(
        request,
        user,
        invites=_decorate_invites(items),
        total=total,
        page=page,
        per_page=per_page,
        error=None,
        created=None,
        status_code=200,
    )


@app.post("/admin/invites")
async def admin_invites_create(
    request: Request,
    expires_in_hours: Annotated[int, Form(ge=1, le=_INVITE_MAX_EXPIRES_HOURS)],
    max_uses: Annotated[int | None, Form()] = 1,
    role: Annotated[str, Form()] = "user",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_INVITES_MAX_PER_PAGE),
    ] = _ADMIN_INVITES_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    # Treat 0 or empty as unlimited (0 in the API).
    effective_max_uses = max_uses if max_uses and max_uses > 0 else 0
    # Sanitize role — only "user" and "admin" are valid.
    effective_role = role if role in ("user", "admin") else "user"

    try:
        created = await auth_client.admin_create_invite(
            settings.auth_service_url,
            user.token,
            expires_in_hours,
            effective_max_uses,
            role=effective_role,
        )
    except auth_client.AuthForbidden:
        _log.info("admin.invites.create.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth POST /admin/invites call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    invites, total = await _refetch_admin_invites(settings, user, page=page, per_page=per_page)
    # The plaintext token is one-shot — surface it inline; the next
    # GET /admin/invites navigation will re-render without it.
    return _render_admin_invites(
        request,
        user,
        invites=invites,
        total=total,
        page=page,
        per_page=per_page,
        error=None,
        created={
            "id": created.id,
            "token": created.token,
            "expires_at": created.expires_at,
            "invite_url": _invite_url(request, created.token),
        },
        status_code=200,
    )


@app.post("/admin/invites/{invite_id}/revoke")
async def admin_invites_revoke(
    invite_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_INVITES_MAX_PER_PAGE),
    ] = _ADMIN_INVITES_DEFAULT_PER_PAGE,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        ok, err = await auth_client.admin_revoke_invite(
            settings.auth_service_url, user.token, str(invite_id)
        )
    except auth_client.AuthForbidden:
        _log.info("admin.invites.revoke.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth DELETE /admin/invites call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        return RedirectResponse(
            url=f"/admin/invites?page={page}&per_page={per_page}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    invites, total = await _refetch_admin_invites(settings, user, page=page, per_page=per_page)
    if err == "invite_not_found":
        message = "That invite no longer exists."
        code = status.HTTP_404_NOT_FOUND
    else:
        message = "Could not revoke invite."
        code = status.HTTP_400_BAD_REQUEST
    return _render_admin_invites(
        request,
        user,
        invites=invites,
        total=total,
        page=page,
        per_page=per_page,
        error=message,
        created=None,
        status_code=code,
    )


# ---------------------------------------------------------------------------
# Admin matches — system-wide match view (ROADMAP #11)
# ---------------------------------------------------------------------------


_ADMIN_MATCHES_DEFAULT_PER_PAGE = 20
_ADMIN_MATCHES_MAX_PER_PAGE = 100

_MATCH_FORMAT_OPTIONS = [
    "Standard",
    "Pioneer",
    "Modern",
    "Legacy",
    "Vintage",
    "Pauper",
    "Commander",
    "Draft",
    "Sealed",
    "Historic",
    "Premodern",
    "Cube",
]


_VALID_REVIEW_STATUS_FILTERS = {"all", "pending_review", "rejected", "normal"}
# Accept verdicts the admin can post via the inline action buttons.
# ``""`` encodes "accept" (back to NULL); the form posts the verdict as
# a string and we translate to ``None`` on the way to the JSON client.
_VALID_REVIEW_VERDICT_FORM_VALUES = {"", "pending_review", "rejected"}


@app.get("/admin/matches", response_class=HTMLResponse)
async def admin_matches_list(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_MATCHES_MAX_PER_PAGE),
    ] = _ADMIN_MATCHES_DEFAULT_PER_PAGE,
    format: Annotated[str, Query(alias="format")] = "",
    opponent: Annotated[str, Query()] = "",
    result: Annotated[str, Query()] = "",
    date_from: Annotated[str, Query()] = "",
    date_to: Annotated[str, Query()] = "",
    review_status: Annotated[str, Query()] = "",
    msg: Annotated[str, Query()] = "",
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    review_status_clean = review_status.lower() if review_status else ""
    if review_status_clean and review_status_clean not in _VALID_REVIEW_STATUS_FILTERS:
        review_status_clean = ""

    filters = {
        "format": format,
        "opponent": opponent,
        "result": result,
        "date_from": date_from,
        "date_to": date_to,
        "review_status": review_status_clean,
    }
    filter_qs = urlencode({k: v for k, v in filters.items() if v})
    # Only carry a non-default page size on the chips, so an unfiltered view
    # keeps a clean /admin/matches URL.
    chip_per_page = per_page if per_page != _ADMIN_MATCHES_DEFAULT_PER_PAGE else None

    try:
        match_list = await analytics_client.admin_list_matches(
            settings.analytics_service_url,
            user.token,
            page=page,
            per_page=per_page,
            format_filter=format or None,
            opponent=opponent or None,
            result=result or None,
            date_from=date_from or None,
            date_to=date_to or None,
            review_status=review_status_clean or None,
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.matches.list.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /admin/matches call failed")
        return templates.TemplateResponse(
            request,
            "admin_matches.html",
            {
                "user": user,
                "match_list": None,
                "filters": filters,
                "filter_qs": filter_qs,
                "chip_per_page": chip_per_page,
                "format_options": _MATCH_FORMAT_OPTIONS,
                "error": "Analytics service unavailable. Please try again.",
                "msg": msg,
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return templates.TemplateResponse(
        request,
        "admin_matches.html",
        {
            "user": user,
            "match_list": match_list,
            "filters": filters,
            "filter_qs": filter_qs,
            "chip_per_page": chip_per_page,
            "format_options": _MATCH_FORMAT_OPTIONS,
            "error": None,
            "msg": msg,
        },
    )


@app.get("/admin/matches/{match_id}", response_class=HTMLResponse)
async def admin_match_detail_page(
    match_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Admin match detail — can view any user's match regardless of review status."""
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    try:
        match = await analytics_client.admin_get_match_detail(
            settings.analytics_service_url, user.token, str(match_id)
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.matches.detail.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /matches/admin/%s call failed", match_id)
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if match is None:
        return Response(content="Match not found.", status_code=status.HTTP_404_NOT_FOUND)

    overall_result = ""
    if match.players and match.games:
        hero = match.hero_player_name or match.players[0]
        user_wins = sum(1 for g in match.games if g.winner == hero)
        opp_wins = sum(1 for g in match.games if g.winner is not None and g.winner != hero)
        if user_wins > opp_wins:
            overall_result = "W"
        elif user_wins < opp_wins:
            overall_result = "L"
        elif user_wins or opp_wins:
            overall_result = "D"
    return templates.TemplateResponse(
        request,
        "match_detail.html",
        {
            "user": user,
            "match": match,
            "overall_result": overall_result,
            "review_status": match.review_status,
            "review_reason": match.review_reason,
            "format_options": _MATCH_FORMAT_OPTIONS,
            "admin_view": True,
        },
    )


@app.post("/admin/matches/{match_id}/review")
async def admin_match_set_review_status(
    match_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    # ``verdict`` is intentionally optional: the Accept button submits
    # an empty string (which encodes "back to NULL = user-visible").
    # Newer FastAPI versions reject empty form fields when the param is
    # typed as a required ``str``; a default value keeps the form
    # working without making the field optional in the template.
    verdict: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "",
) -> Response:
    """Accept, reject, or flag a match.

    ``verdict`` is one of ``""`` (accept → back to NULL),
    ``"pending_review"`` (flag for admin review), or ``"rejected"``
    (permanently discard). Anything else 422s.
    """
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    if verdict not in _VALID_REVIEW_VERDICT_FORM_VALUES:
        return Response(
            content="Invalid verdict.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    new_review_status: str | None = verdict if verdict else None

    try:
        item, err = await analytics_client.admin_set_match_review_status(
            settings.analytics_service_url,
            user.token,
            str(match_id),
            new_review_status,
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.matches.review.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /admin/matches/%s/review failed", match_id)
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if item is None and err == "match_not_found":
        msg = "That match no longer exists."
    elif item is None:
        msg = "Could not update match."
    elif new_review_status is None:
        msg = "Match accepted."
    elif new_review_status == "rejected":
        msg = "Match rejected."
    else:
        msg = "Match flagged for review."

    target = _safe_next(return_to) if return_to else "/admin/matches"
    sep = "&" if "?" in target else "?"
    return RedirectResponse(
        url=f"{target}{sep}{urlencode({'msg': msg})}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Admin archetype catalog
# ---------------------------------------------------------------------------


def _parse_defining_cards(raw: str) -> list[str]:
    """Split the textarea body into a clean list of card names.

    The form is one card per line; whitespace-only lines are dropped
    and each entry is stripped. Order is preserved.
    """
    return [line.strip() for line in raw.splitlines() if line.strip()]


@app.get("/admin/archetypes", response_class=HTMLResponse)
async def admin_archetypes_list(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        items, total = await analytics_client.admin_list_archetypes(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.archetypes.list.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /archetypes call failed")
        return templates.TemplateResponse(
            request,
            "admin_archetypes.html",
            {
                "user": user,
                "archetypes": [],
                "total": 0,
                "error": "Analytics service unavailable. Please try again.",
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return templates.TemplateResponse(
        request,
        "admin_archetypes.html",
        {
            "user": user,
            "archetypes": items,
            "total": total,
            "error": None,
        },
    )


@app.get("/admin/archetypes/new", response_class=HTMLResponse)
async def admin_archetypes_new_form(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    return templates.TemplateResponse(
        request,
        "admin_archetypes_edit.html",
        {
            "user": user,
            "mode": "create",
            "archetype_id": None,
            "name": "",
            "format": "",
            "defining_cards_text": "",
            "error": None,
        },
    )


@app.post("/admin/archetypes/create")
async def admin_archetypes_create(
    request: Request,
    name: Annotated[str, Form()],
    format: Annotated[str, Form()],
    defining_cards: Annotated[str, Form()] = "",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    submitted_name = name.strip()
    submitted_format = format.strip()
    cards = _parse_defining_cards(defining_cards or "")

    def _render_error(message: str, code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "admin_archetypes_edit.html",
            {
                "user": user,
                "mode": "create",
                "archetype_id": None,
                "name": submitted_name,
                "format": submitted_format,
                "defining_cards_text": (defining_cards or ""),
                "error": message,
            },
            status_code=code,
        )

    if not submitted_name:
        return _render_error("Name is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_format:
        return _render_error("Format is required.", status.HTTP_400_BAD_REQUEST)

    try:
        item, err = await analytics_client.admin_create_archetype(
            settings.analytics_service_url,
            user.token,
            name=submitted_name,
            format_=submitted_format,
            defining_cards=cards,
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.archetypes.create.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /archetypes call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if item is None:
        return _render_error(
            "Could not create archetype.",
            status.HTTP_400_BAD_REQUEST if err == "invalid_input" else status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(url="/admin/archetypes", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/archetypes/{archetype_id}/edit", response_class=HTMLResponse)
async def admin_archetypes_edit_form(
    archetype_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        item = await analytics_client.admin_get_archetype(
            settings.analytics_service_url, user.token, str(archetype_id)
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.archetypes.edit.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /archetypes/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if item is None:
        return Response(
            content="That archetype no longer exists.",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return templates.TemplateResponse(
        request,
        "admin_archetypes_edit.html",
        {
            "user": user,
            "mode": "edit",
            "archetype_id": item.id,
            "name": item.name,
            "format": item.format,
            "defining_cards_text": "\n".join(item.defining_cards),
            "error": None,
        },
    )


@app.post("/admin/archetypes/{archetype_id}/edit")
async def admin_archetypes_edit(
    archetype_id: uuid.UUID,
    request: Request,
    name: Annotated[str, Form()],
    format: Annotated[str, Form()],
    defining_cards: Annotated[str, Form()] = "",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    submitted_name = name.strip()
    submitted_format = format.strip()
    cards = _parse_defining_cards(defining_cards or "")

    def _render_error(message: str, code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "admin_archetypes_edit.html",
            {
                "user": user,
                "mode": "edit",
                "archetype_id": str(archetype_id),
                "name": submitted_name,
                "format": submitted_format,
                "defining_cards_text": (defining_cards or ""),
                "error": message,
            },
            status_code=code,
        )

    if not submitted_name:
        return _render_error("Name is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_format:
        return _render_error("Format is required.", status.HTTP_400_BAD_REQUEST)

    try:
        item, err = await analytics_client.admin_update_archetype(
            settings.analytics_service_url,
            user.token,
            str(archetype_id),
            name=submitted_name,
            format_=submitted_format,
            defining_cards=cards,
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.archetypes.update.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics PUT /archetypes/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if err == "archetype_not_found":
        return _render_error("That archetype no longer exists.", status.HTTP_404_NOT_FOUND)
    if item is None:
        return _render_error("Could not update archetype.", status.HTTP_400_BAD_REQUEST)
    return RedirectResponse(url="/admin/archetypes", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/archetypes/{archetype_id}/delete")
async def admin_archetypes_delete(
    archetype_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        ok, err = await analytics_client.admin_delete_archetype(
            settings.analytics_service_url, user.token, str(archetype_id)
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.archetypes.delete.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics DELETE /archetypes/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        return RedirectResponse(url="/admin/archetypes", status_code=status.HTTP_303_SEE_OTHER)

    if err == "archetype_not_found":
        try:
            items, total = await analytics_client.admin_list_archetypes(
                settings.analytics_service_url, user.token
            )
        except (analytics_client.AnalyticsClientError, analytics_client.AnalyticsForbidden):
            items, total = [], 0
        return templates.TemplateResponse(
            request,
            "admin_archetypes.html",
            {
                "user": user,
                "archetypes": items,
                "total": total,
                "error": "That archetype no longer exists.",
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return Response(
        content="Could not delete archetype.",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


# ---------------------------------------------------------------------------
# Admin B&R Events — CRUD + wiki import
# ---------------------------------------------------------------------------


def _parse_card_actions(raw: str) -> list[dict]:
    """Parse card actions from a textarea.

    Each line is ``Card Name | action``. Returns a list of dicts
    like ``[{"card": "Fury", "action": "banned"}]``. Lines that
    don't match the pattern are silently ignored.
    """
    actions: list[dict] = []
    valid_actions = {"banned", "unbanned", "restricted", "unrestricted", "suspended"}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "|" not in line:
            continue
        parts = line.rsplit("|", 1)
        card = parts[0].strip()
        action = parts[1].strip().lower()
        if card and action in valid_actions:
            actions.append({"card": card, "action": action})
    return actions


@app.get("/admin/bnr-events", response_class=HTMLResponse)
async def admin_bnr_events_list(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    error = request.query_params.get("error")
    success = request.query_params.get("success")

    try:
        items, total = await analytics_client.admin_list_bnr_events(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.bnr_events.list.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /bnr-events call failed")
        return templates.TemplateResponse(
            request,
            "admin_bnr_events.html",
            {
                "user": user,
                "events": [],
                "total": 0,
                "error": "Analytics service unavailable. Please try again.",
                "success": None,
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return templates.TemplateResponse(
        request,
        "admin_bnr_events.html",
        {
            "user": user,
            "events": items,
            "total": total,
            "error": error,
            "success": success,
        },
    )


@app.get("/admin/bnr-events/new", response_class=HTMLResponse)
async def admin_bnr_events_new_form(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked
    return templates.TemplateResponse(
        request,
        "admin_bnr_events_edit.html",
        {
            "user": user,
            "mode": "create",
            "event_id": None,
            "description": "",
            "format": "",
            "effective_date": "",
            "card_actions_text": "",
            "error": None,
        },
    )


@app.post("/admin/bnr-events/create")
async def admin_bnr_events_create(
    request: Request,
    description: Annotated[str, Form()],
    format: Annotated[str, Form()],
    effective_date: Annotated[str, Form()],
    card_actions: Annotated[str, Form()] = "",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    submitted_description = description.strip()
    submitted_format = format.strip()
    submitted_date = effective_date.strip()
    actions = _parse_card_actions(card_actions or "")

    def _render_error(message: str, code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "admin_bnr_events_edit.html",
            {
                "user": user,
                "mode": "create",
                "event_id": None,
                "description": submitted_description,
                "format": submitted_format,
                "effective_date": submitted_date,
                "card_actions_text": (card_actions or ""),
                "error": message,
            },
            status_code=code,
        )

    if not submitted_description:
        return _render_error("Description is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_format:
        return _render_error("Format is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_date:
        return _render_error("Effective date is required.", status.HTTP_400_BAD_REQUEST)

    try:
        item, err = await analytics_client.admin_create_bnr_event(
            settings.analytics_service_url,
            user.token,
            format_=submitted_format,
            effective_date=submitted_date,
            description=submitted_description,
            card_actions=actions,
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.bnr_events.create.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /bnr-events call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if item is None:
        return _render_error(
            "Could not create B&R event.",
            status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(url="/admin/bnr-events", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/bnr-events/{event_id}/edit", response_class=HTMLResponse)
async def admin_bnr_events_edit_form(
    event_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        item = await analytics_client.admin_get_bnr_event(
            settings.analytics_service_url, user.token, str(event_id)
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.bnr_events.edit.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /bnr-events/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    if item is None:
        return Response(
            content="That B&R event no longer exists.",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    # Build card_actions_text from the stored actions
    lines = []
    for ca in item.card_actions:
        card = ca.get("card", "")
        action = ca.get("action", "")
        if card and action:
            lines.append(f"{card} | {action}")
    return templates.TemplateResponse(
        request,
        "admin_bnr_events_edit.html",
        {
            "user": user,
            "mode": "edit",
            "event_id": item.id,
            "description": item.description,
            "format": item.format,
            "effective_date": item.effective_date,
            "card_actions_text": "\n".join(lines),
            "error": None,
        },
    )


@app.post("/admin/bnr-events/{event_id}/edit")
async def admin_bnr_events_edit(
    event_id: uuid.UUID,
    request: Request,
    description: Annotated[str, Form()],
    format: Annotated[str, Form()],
    effective_date: Annotated[str, Form()],
    card_actions: Annotated[str, Form()] = "",
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    submitted_description = description.strip()
    submitted_format = format.strip()
    submitted_date = effective_date.strip()
    actions = _parse_card_actions(card_actions or "")

    def _render_error(message: str, code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "admin_bnr_events_edit.html",
            {
                "user": user,
                "mode": "edit",
                "event_id": str(event_id),
                "description": submitted_description,
                "format": submitted_format,
                "effective_date": submitted_date,
                "card_actions_text": (card_actions or ""),
                "error": message,
            },
            status_code=code,
        )

    if not submitted_description:
        return _render_error("Description is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_format:
        return _render_error("Format is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_date:
        return _render_error("Effective date is required.", status.HTTP_400_BAD_REQUEST)

    try:
        item, err = await analytics_client.admin_update_bnr_event(
            settings.analytics_service_url,
            user.token,
            str(event_id),
            format_=submitted_format,
            effective_date=submitted_date,
            description=submitted_description,
            card_actions=actions,
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.bnr_events.update.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics PUT /bnr-events/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if err == "bnr_event_not_found":
        return _render_error("That B&R event no longer exists.", status.HTTP_404_NOT_FOUND)
    if item is None:
        return _render_error("Could not update B&R event.", status.HTTP_400_BAD_REQUEST)
    return RedirectResponse(url="/admin/bnr-events", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/bnr-events/{event_id}/delete")
async def admin_bnr_events_delete(
    event_id: uuid.UUID,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        ok, err = await analytics_client.admin_delete_bnr_event(
            settings.analytics_service_url, user.token, str(event_id)
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.bnr_events.delete.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics DELETE /bnr-events/{id} call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        return RedirectResponse(url="/admin/bnr-events", status_code=status.HTTP_303_SEE_OTHER)

    if err == "bnr_event_not_found":
        return RedirectResponse(
            url="/admin/bnr-events?error=That+event+no+longer+exists.",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return Response(
        content="Could not delete B&R event.",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@app.post("/admin/bnr-events/import-wiki")
async def admin_bnr_events_import_wiki(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        result = await analytics_client.admin_import_bnr_wiki(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.bnr_events.import_wiki.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /bnr-events/import-wiki call failed")
        return RedirectResponse(
            url="/admin/bnr-events?error=Wiki+import+failed.+Analytics+service+unavailable.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    imported = result.get("imported", 0)
    skipped = result.get("skipped", 0)
    errors = result.get("errors", [])
    parts = [f"Imported {imported}", f"skipped {skipped}"]
    if errors:
        parts.append(f"errors: {len(errors)}")
    msg = ", ".join(parts) + "."
    param = "success" if not errors else "error"
    return RedirectResponse(
        url=f"/admin/bnr-events?{param}={msg.replace(' ', '+')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# Admin cards — Scryfall mirror status + manual sync
# ---------------------------------------------------------------------------


def _render_admin_cards(
    request: Request,
    user: BrowserUser,
    *,
    cards_status_view: dict[str, Any] | None,
    error: str | None,
    synced: bool,
    status_code: int,
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin_cards.html",
        {
            "user": user,
            "cards_status": cards_status_view,
            "error": error,
            "synced": synced,
        },
        status_code=status_code,
    )


@app.get("/admin/cards", response_class=HTMLResponse)
async def admin_cards_page(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    synced: Annotated[int, Query(ge=0, le=1)] = 0,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    cards_status_view: dict[str, Any] | None = None
    error: str | None = None
    try:
        cards_status_view = await analytics_client.admin_get_cards_status(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.cards.status.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /admin/cards-status call failed")
        error = "Analytics service unavailable. Please try again."

    code = status.HTTP_503_SERVICE_UNAVAILABLE if error and cards_status_view is None else 200
    return _render_admin_cards(
        request,
        user,
        cards_status_view=cards_status_view,
        error=error,
        synced=synced == 1,
        status_code=code,
    )


@app.post("/admin/cards/sync")
async def admin_cards_sync(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        await analytics_client.admin_trigger_sync(settings.analytics_service_url, user.token)
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.cards.sync.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics POST /admin/sync-cards call failed")
        return Response(
            content="Analytics service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    return RedirectResponse(url="/admin/cards?synced=1", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Public registration — W3.6.4
# ---------------------------------------------------------------------------


def _render_register(
    request: Request,
    *,
    mode: str,
    token: str | None,
    email: str,
    error: str | None,
    invite_only_no_token: bool,
    status_code: int,
) -> Response:
    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "user": None,  # public page; no nav user
            "mode": mode,
            "token": token,
            "email": email,
            "error": error,
            "invite_only_no_token": invite_only_no_token,
        },
        status_code=status_code,
    )


@app.get("/register", response_class=HTMLResponse)
async def register_form(
    request: Request,
    token: Annotated[str | None, Query()] = None,
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Public registration landing.

    - ``invite_only`` mode + missing/blank token: render the
      "registration is invite-only" message (no form).
    - ``invite_only`` mode + token present: render form, pass token
      through as a hidden field; auth validates on submit.
    - ``open`` mode: render the form unconditionally; token is optional
      (consumed for audit if present).
    """
    mode = await auth_client.public_get_registration_mode(settings.auth_service_url)
    has_token = bool((token or "").strip())
    invite_only_no_token = mode == "invite_only" and not has_token
    return _render_register(
        request,
        mode=mode,
        token=token,
        email="",
        error=None,
        invite_only_no_token=invite_only_no_token,
        status_code=200,
    )


@app.post("/register")
async def register_submit(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    token: Annotated[str, Form()] = "",
    settings: WebSettings = Depends(get_settings),
) -> Response:
    submitted_email = email.strip()
    submitted_token = (token or "").strip() or None
    mode = await auth_client.public_get_registration_mode(settings.auth_service_url)

    def _err(message: str, code: int) -> Response:
        return _render_register(
            request,
            mode=mode,
            token=submitted_token,
            email=submitted_email,
            error=message,
            invite_only_no_token=False,
            status_code=code,
        )

    if password != confirm_password:
        return _err("Passwords do not match.", status.HTTP_400_BAD_REQUEST)
    if not password:
        return _err("Password is required.", status.HTTP_400_BAD_REQUEST)
    if not submitted_email:
        return _err("Email is required.", status.HTTP_400_BAD_REQUEST)

    try:
        ok, err = await auth_client.public_register(
            settings.auth_service_url,
            submitted_email,
            password,
            submitted_token,
        )
    except auth_client.EmailAlreadyTaken:
        return _err(
            "An account with this email already exists. Try logging in or use a different address.",
            status.HTTP_409_CONFLICT,
        )
    except auth_client.AuthClientError:
        _log.exception("auth POST /auth/register call failed")
        return _err(
            "Authentication service unavailable. Please try again.",
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if ok:
        # Land them on /login with a success hint via the email field.
        # Auth deliberately doesn't auto-login — it keeps the
        # registration path stateless and forces an explicit credential
        # round-trip before any session cookie is set.
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    if err == "invite_required":
        return _render_register(
            request,
            mode=mode,
            token=None,
            email=submitted_email,
            error=None,
            invite_only_no_token=True,
            status_code=status.HTTP_403_FORBIDDEN,
        )
    if err == "invalid_invite_token":
        return _err(
            "That invite token is invalid, expired, or already used.",
            status.HTTP_403_FORBIDDEN,
        )
    if err == "email_already_exists":
        return _err(
            "An account with that email already exists.",
            status.HTTP_409_CONFLICT,
        )
    if err == "weak_password":
        return _err(
            "Password does not meet complexity requirements (minimum 12 characters).",
            status.HTTP_400_BAD_REQUEST,
        )
    if err == "invalid_email":
        return _err("Email address is not valid.", status.HTTP_400_BAD_REQUEST)
    return _err("Could not register account.", status.HTTP_400_BAD_REQUEST)


@app.post("/logout")
async def logout(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> Response:
    # Best-effort server-side revoke if a valid-looking token is
    # present. We don't require full browser-auth here — if the
    # cookie is corrupt, the user still gets a clean logout.
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        await auth_client.logout(settings.auth_service_url, token)

    redirect = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookie(redirect)
    return redirect
