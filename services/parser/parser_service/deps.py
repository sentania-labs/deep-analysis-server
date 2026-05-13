"""FastAPI dependencies for the parser service.

Auth follows the same JWT-based pattern as analytics: the access
token's signature + expiry is enough for mutation endpoints. User
endpoints require any valid JWT; admin endpoints additionally
require the ``admin`` role claim.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from common.jwt_verify import InvalidTokenError, JWTVerifier
from parser_service.settings import get_settings


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
