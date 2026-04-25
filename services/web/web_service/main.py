"""Web service — admin UI shell + browser auth.

This service serves the browser-facing admin UI. Browser sessions use
a cookie-carried JWT (``da_session``); API consumers continue to hit
/auth/* on the auth service with a Bearer header. The two paths are
independent and coexist in the compose stack.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, Request, Response, status
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
