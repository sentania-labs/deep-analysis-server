"""Web service — admin UI shell + browser auth.

This service serves the browser-facing admin UI. Browser sessions use
a cookie-carried JWT (``da_session``); API consumers continue to hit
/auth/* on the auth service with a Bearer header. The two paths are
independent and coexist in the compose stack.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from common.logging import configure_logging
from common.metrics import mount_metrics
from web_service import auth_client
from web_service.deps import (
    BrowserAuthRedirect,
    BrowserUser,
    browser_auth_redirect_handler,
    get_current_browser_user,
    get_current_browser_user_any_scope,
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
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Browser-auth redirect handler — converts BrowserAuthRedirect into a
# 302 to /login (or /settings/password for password-change scope).
app.add_exception_handler(BrowserAuthRedirect, browser_auth_redirect_handler)


@app.get("/healthz")
@app.get("/web/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


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
        redirect = RedirectResponse(url=_safe_next(next), status_code=status.HTTP_303_SEE_OTHER)

    _set_session_cookie(redirect, result.access_token, result.expires_in)
    return redirect


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user},
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


@app.get("/profile", response_class=HTMLResponse)
async def profile(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    try:
        me = await auth_client.get_me(settings.auth_service_url, user.token)
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
    try:
        me = await auth_client.get_me(settings.auth_service_url, user.token)
    except auth_client.AuthClientError:
        _log.exception("auth /me call failed")
        return _service_unavailable(request, user)
    return templates.TemplateResponse(
        request,
        "profile_edit.html",
        {"user": user, "email": me.email, "error": None},
    )


@app.post("/profile/edit")
async def profile_edit_submit(
    request: Request,
    email: Annotated[str, Form()],
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    submitted = email.strip()

    def _render_error(message: str, code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "profile_edit.html",
            {"user": user, "email": submitted, "error": message},
            status_code=code,
        )

    if not submitted:
        return _render_error("Email is required.", status.HTTP_400_BAD_REQUEST)

    try:
        ok, err = await auth_client.update_me(settings.auth_service_url, user.token, submitted)
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

    if ok:
        return RedirectResponse(url="/profile", status_code=status.HTTP_303_SEE_OTHER)
    if err == "email_taken":
        return _render_error(
            "That email is already in use by another account.",
            status.HTTP_409_CONFLICT,
        )
    if err == "invalid_email":
        return _render_error(
            "Email address is not valid.",
            status.HTTP_400_BAD_REQUEST,
        )
    return _render_error(
        "Could not update profile.",
        status.HTTP_400_BAD_REQUEST,
    )


@app.get("/profile/agents", response_class=HTMLResponse)
async def profile_agents(
    request: Request,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    try:
        agents = await auth_client.list_my_agents(settings.auth_service_url, user.token)
    except auth_client.AuthClientError:
        _log.exception("auth /me/agents call failed")
        return _service_unavailable(request, user)
    return templates.TemplateResponse(
        request,
        "profile_agents.html",
        {"user": user, "agents": agents},
    )


@app.post("/profile/agents/{agent_id}/revoke")
async def profile_agents_revoke(
    agent_id: str,
    user: BrowserUser = Depends(get_current_browser_user),
    settings: WebSettings = Depends(get_settings),
) -> Response:
    try:
        ok, err = await auth_client.revoke_my_agent(settings.auth_service_url, user.token, agent_id)
    except auth_client.AuthClientError:
        _log.exception("auth /me/agents revoke call failed")
        return Response(
            content="Authentication service unavailable. Please try again.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    # 403/404 still bounce to the list — listing will reflect current
    # state (or omit the agent), which is the user-facing truth.
    if not ok:
        _log.info("profile.agent_revoke.rejected", extra={"err": err})
    return RedirectResponse(url="/profile/agents", status_code=status.HTTP_303_SEE_OTHER)


def _service_unavailable(request: Request, user: BrowserUser) -> Response:
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "user": user,
            "me": None,
            "error": "Authentication service unavailable. Please try again.",
        },
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
