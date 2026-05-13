"""Web service — admin UI shell + browser auth.

This service serves the browser-facing admin UI. Browser sessions use
a cookie-carried JWT (``da_session``); API consumers continue to hit
/auth/* on the auth service with a Bearer header. The two paths are
independent and coexist in the compose stack.
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from common.logging import configure_logging
from common.metrics import mount_metrics
from web_service import analytics_client, auth_client, parser_client
from web_service.deps import (
    BrowserAuthRedirect,
    BrowserUser,
    browser_auth_redirect_handler,
    get_current_browser_user,
    get_current_browser_user_any_scope,
    get_verifier,
)
from web_service.settings import WebSettings, get_settings

SERVICE_NAME = "web"
configure_logging(SERVICE_NAME)
_log = logging.getLogger("web.main")

_PACKAGE_ROOT = Path(__file__).resolve().parent
_TEMPLATES_DIR = _PACKAGE_ROOT / "templates"
_STATIC_DIR = _PACKAGE_ROOT / "static"

app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}")
mount_metrics(app, SERVICE_NAME)

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
templates.env.globals["app_version"] = os.environ.get("APP_VERSION", "dev")
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Browser-auth redirect handler — converts BrowserAuthRedirect into a
# 302 to /login (or /settings/password for password-change scope).
app.add_exception_handler(BrowserAuthRedirect, browser_auth_redirect_handler)


@app.get("/healthz")
@app.get("/web/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


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


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    if user.role == "admin":
        return RedirectResponse(url=_ADMIN_LANDING_PATH, status_code=status.HTTP_302_FOUND)

    stats_summary: Any = None
    format_stats: list[Any] = []
    opponent_stats: list[Any] = []
    stats_error = False
    try:
        stats_summary = await analytics_client.get_stats_summary(
            settings.analytics_service_url, user.token
        )
        format_stats = await analytics_client.get_stats_by_format(
            settings.analytics_service_url, user.token
        )
        opponent_stats = await analytics_client.get_stats_by_opponent(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        # Treat as logged-out: bounce to /login so the user can re-auth.
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics stats call failed; rendering dashboard with error banner")
        stats_error = True

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "stats_summary": stats_summary,
            "format_stats": format_stats,
            "opponent_stats": opponent_stats,
            "stats_error": stats_error,
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


@app.post("/profile/agents/reingest")
async def profile_agents_reingest(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    """Force reingest: delete all parsed matches for the current user."""
    bounce = _bounce_admin_to_panel(user)
    if bounce is not None:
        return bounce
    try:
        result = await parser_client.delete_my_matches(settings.parser_service_url, user.token)
    except parser_client.ParserForbidden:
        _log.info("profile.agents.reingest.forbidden", extra={"user_id": user.user_id})
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    except parser_client.ParserClientError:
        _log.exception("parser DELETE /parser/matches call failed")
        return Response(
            content="Parser service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # Re-render the agents page with the reingest result.
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
            "reingest_result": result,
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

    # Compute overall W/L/D from the games list using the same
    # "uploader is players[0]" convention the dashboard uses.
    overall_result = ""
    if match.players and match.games:
        uploader = match.players[0]
        user_wins = sum(1 for g in match.games if g.winner == uploader)
        opp_wins = sum(1 for g in match.games if g.winner is not None and g.winner != uploader)
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
        temp, err = await auth_client.admin_reset_password(
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

    if temp is not None:
        result = {"user_id": user_id, "temporary_password": temp}
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


@app.post("/admin/agents/{user_id}/reingest")
async def admin_agent_reingest(
    user_id: int,
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[
        int,
        Query(ge=1, le=_ADMIN_AGENTS_MAX_PER_PAGE),
    ] = _ADMIN_AGENTS_DEFAULT_PER_PAGE,
) -> Response:
    """Admin: force reingest for a specific user."""
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        result = await parser_client.admin_delete_user_matches(
            settings.parser_service_url, user.token, user_id
        )
    except parser_client.ParserForbidden:
        _log.info("admin.agents.reingest.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except parser_client.ParserClientError:
        _log.exception("parser DELETE /parser/admin/matches/%s call failed", user_id)
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
            "reingest_result": result,
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
    error: str | None,
    saved: bool,
    status_code: int,
) -> Response:
    return templates.TemplateResponse(
        request,
        "admin_settings.html",
        {
            "user": user,
            "mode": mode,
            "is_root_admin": user.user_id == _ROOT_ADMIN_USER_ID,
            "lock_tooltip": _REGISTRATION_MODE_LOCK_TOOLTIP,
            "error": error,
            "saved": saved,
        },
        status_code=status_code,
    )


@app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
    saved: Annotated[int, Query(ge=0, le=1)] = 0,
) -> Response:
    blocked = _require_admin_or_403(request, user)
    if blocked is not None:
        return blocked

    try:
        mode = await auth_client.admin_get_registration_mode(settings.auth_service_url, user.token)
    except auth_client.AuthForbidden:
        _log.info("admin.settings.get.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except auth_client.AuthClientError:
        _log.exception("auth /admin/settings/registration-mode call failed")
        return _render_admin_settings(
            request,
            user,
            mode=None,
            error="Authentication service unavailable. Please try again.",
            saved=False,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _render_admin_settings(
        request,
        user,
        mode=mode,
        error=None,
        saved=saved == 1,
        status_code=200,
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
        created = await auth_client.admin_create_invite(
            settings.auth_service_url, user.token, expires_in_hours
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
# Admin cards — Scryfall mirror status + manual sync
# ---------------------------------------------------------------------------


def _render_admin_cards(
    request: Request,
    user: BrowserUser,
    *,
    cards_status_view: dict[str, Any] | None,
    scraper_health: dict[str, Any] | None,
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
            "scraper_health": scraper_health,
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
    scraper_health: dict[str, Any] | None = None
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

    try:
        scraper_health = await analytics_client.admin_get_scraper_health(
            settings.analytics_service_url, user.token
        )
    except analytics_client.AnalyticsForbidden:
        _log.info("admin.cards.health.forbidden", extra={"user_id": user.user_id})
        return _admin_forbidden(request, user)
    except analytics_client.AnalyticsClientError:
        _log.exception("analytics GET /admin/scraper-health call failed")
        # Surface partial data — the status panel is independent of the
        # scraper-health panel. Avoid overwriting an earlier error.
        if error is None:
            error = "Scraper health unavailable. Please try again."

    code = (
        status.HTTP_503_SERVICE_UNAVAILABLE
        if error and cards_status_view is None and scraper_health is None
        else 200
    )
    return _render_admin_cards(
        request,
        user,
        cards_status_view=cards_status_view,
        scraper_health=scraper_health,
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
