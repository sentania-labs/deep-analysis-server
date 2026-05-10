"""FastAPI dependencies for the analytics service.

Auth is JWT-based (the same RS256 access tokens auth issues for users).
Analytics doesn't carry an authoritative session check the way auth
does — the access token's signature + expiry is enough for read-only
catalog access. Mutation endpoints additionally require the ``admin``
role claim.

The classify endpoint is intentionally unauthenticated: it is a
stateless utility so the parser worker (which holds no JWT of its own)
can call it after persisting a match. The endpoint surfaces no data
from the catalog beyond the matched archetype's id/name/format, all of
which are already enumerable by any logged-in user via GET /archetypes.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from analytics_service.settings import get_settings
from common.jwt_verify import InvalidTokenError, JWTVerifier


@dataclass
class AuthenticatedUser:
    user_id: int
    role: str


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


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized"},
    )


def _forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "forbidden"},
    )


def _resolve_user(request: Request) -> AuthenticatedUser:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise _unauthorized()
    token = auth[7:].strip()
    if not token:
        raise _unauthorized()
    try:
        claims = get_verifier().verify(token)
    except InvalidTokenError as exc:
        raise _unauthorized() from exc
    try:
        user_id = int(claims["sub"])
        role = str(claims["role"])
    except (KeyError, ValueError) as exc:
        raise _unauthorized() from exc
    return AuthenticatedUser(user_id=user_id, role=role)


async def require_user(request: Request) -> AuthenticatedUser:
    """Any authenticated caller (user or admin)."""
    return _resolve_user(request)


async def require_admin(request: Request) -> AuthenticatedUser:
    """Authenticated caller with role=admin."""
    user = _resolve_user(request)
    if user.role != "admin":
        raise _forbidden()
    return user
