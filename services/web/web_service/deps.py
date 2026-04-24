"""Browser-session auth for the web service.

The web service authenticates browsers via the ``da_session`` cookie
which carries the same RS256 access-token JWT that API consumers pass
as a Bearer header. Verification is local-only (public-key) — no
network call to auth. If the token is expired, missing, or otherwise
invalid, the user is bounced to /login.

This coexists with the API's Bearer-header auth path; the two never
share a request lifecycle. Browser routes depend on
``get_current_browser_user`` or ``get_current_browser_user_any_scope``;
the /auth/* API routes remain unchanged on the auth service.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse

from common.jwt_verify import InvalidTokenError, JWTVerifier
from web_service.settings import WebSettings, get_settings

PASSWORD_CHANGE_SCOPE = "password-change-only"
PASSWORD_CHANGE_PATH = "/settings/password"


@dataclass
class BrowserUser:
    user_id: int
    email: str
    role: str
    must_change_password: bool
    scope: str | None
    # Raw JWT — needed for service-to-service calls (password change,
    # logout) where we forward the user's token as a Bearer header.
    token: str


class BrowserAuthRedirect(Exception):
    """Signal a redirect instead of a 401.

    Raised by the browser-auth dependency so FastAPI returns a
    RedirectResponse to /login (or the password-change page) instead
    of surfacing a JSON 401. Handled by the app-level exception
    handler registered in main.py.
    """

    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location


_verifier: JWTVerifier | None = None


def get_verifier() -> JWTVerifier:
    global _verifier
    if _verifier is None:
        s = get_settings()
        _verifier = JWTVerifier(s.jwt_public_key_path, s.jwt_issuer, s.jwt_audience)
    return _verifier


def reset_verifier() -> None:
    global _verifier
    _verifier = None


def _login_redirect_for(path: str) -> str:
    # ``next`` echoes the originally-requested path so the login
    # handler can send the user back where they tried to go. The
    # path is URL-encoded (quoted) so exotic bytes can't split the
    # query string. The login handler re-validates with
    # ``_safe_next`` before issuing its own redirect, so an attacker
    # crafting a malicious ``next`` only bounces back to /dashboard.
    if path and path != "/":
        return f"/login?next={quote(path, safe='/')}"
    return "/login"


def _resolve_browser_user(request: Request, settings: WebSettings) -> BrowserUser:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise BrowserAuthRedirect(_login_redirect_for(request.url.path))

    try:
        claims = get_verifier().verify(token)
    except InvalidTokenError as exc:
        raise BrowserAuthRedirect(_login_redirect_for(request.url.path)) from exc

    try:
        user_id = int(claims["sub"])
        role = str(claims["role"])
    except (KeyError, ValueError) as exc:
        raise BrowserAuthRedirect(_login_redirect_for(request.url.path)) from exc

    raw_scope = claims.get("scope")
    scope = raw_scope if isinstance(raw_scope, str) else None
    # The auth service includes an ``email`` claim in tokens it
    # issues; older tokens without it fall back to empty-string and
    # the UI shows "user #<id>" until the next login rotates to a
    # current-format token.
    email_claim = claims.get("email")
    email = str(email_claim) if email_claim else ""

    return BrowserUser(
        user_id=user_id,
        email=email,
        role=role,
        must_change_password=scope == PASSWORD_CHANGE_SCOPE,
        scope=scope,
        token=token,
    )


async def get_current_browser_user(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> BrowserUser:
    """Browser-session auth dep for normal app pages.

    If the session cookie is missing / invalid: redirect to /login.
    If the JWT carries password-change scope AND the caller is not on
    the password-change page: redirect to /settings/password.
    """
    user = _resolve_browser_user(request, settings)
    if user.must_change_password and request.url.path != PASSWORD_CHANGE_PATH:
        raise BrowserAuthRedirect(PASSWORD_CHANGE_PATH)
    return user


async def get_current_browser_user_any_scope(
    request: Request,
    settings: WebSettings = Depends(get_settings),
) -> BrowserUser:
    """Browser-session auth dep that tolerates password-change scope.

    Only the password-change page should use this. Everything else
    depends on ``get_current_browser_user`` which redirects
    password-change-scope sessions to /settings/password.
    """
    return _resolve_browser_user(request, settings)


def browser_auth_redirect_handler(_request: Request, exc: Exception) -> RedirectResponse:
    """Convert BrowserAuthRedirect into a 302.

    Registered on the FastAPI app in main.py. Kept out-of-line from
    the deps module so main.py can import it without dragging in
    FastAPI response imports at dep-resolution time.
    """
    # 303 would force GET semantics, which is the correct choice after
    # a POST. For GET-based redirects (e.g. an expired cookie on
    # /dashboard) both 302 and 303 work; 302 is the conventional
    # choice and matches how the login handler redirects.
    if isinstance(exc, BrowserAuthRedirect):
        return RedirectResponse(url=exc.location, status_code=302)
    # Should never happen — the handler is registered for this exc
    # type only. Defensive fallback to keep types clean.
    return RedirectResponse(url="/login", status_code=302)
