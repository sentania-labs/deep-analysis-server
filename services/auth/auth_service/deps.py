"""FastAPI dependencies — current-user extraction from bearer token."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.db import get_session
from auth_service.models import AgentRegistration, User
from auth_service.models import Session as SessionRow
from auth_service.settings import get_settings
from common.agent_auth import AuthenticatedAgent
from common.jwt_verify import InvalidTokenError, JWTVerifier
from common.token_utils import hash_api_token

PASSWORD_CHANGE_SCOPE = "password-change-only"


@dataclass
class AuthenticatedUser:
    user_id: int
    email: str
    role: str
    session_id: uuid.UUID
    must_change_password: bool
    scope: str | None = None


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


async def _resolve_current_user(
    request: Request,
    db: AsyncSession,
) -> AuthenticatedUser:
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
        session_id = uuid.UUID(claims["sid"])
        user_id = int(claims["sub"])
    except (KeyError, ValueError) as exc:
        raise _unauthorized() from exc

    row = (
        await db.execute(
            select(SessionRow, User)
            .join(User, User.id == SessionRow.user_id)
            .where(SessionRow.id == session_id)
        )
    ).first()
    if row is None:
        raise _unauthorized()
    session_row, user = row
    now = datetime.now(UTC)
    if session_row.revoked_at is not None:
        raise _unauthorized()
    if session_row.expires_at <= now:
        raise _unauthorized()
    if user.id != user_id or user.disabled:
        raise _unauthorized()

    raw_scope = claims.get("scope")
    scope = raw_scope if isinstance(raw_scope, str) else None

    return AuthenticatedUser(
        user_id=user.id,
        email=user.email,
        role=user.role,
        session_id=session_row.id,
        must_change_password=user.must_change_password,
        scope=scope,
    )


def _password_change_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"error": "password_change_required"},
    )


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> AuthenticatedUser:
    """Resolve current user; reject password-change-only tokens.

    Full-scope dep used by endpoints that require a normal access
    token. Endpoints that accept password-change-only tokens must
    instead depend on :func:`get_current_user_any_scope`.
    """
    user = await _resolve_current_user(request, db)
    if user.scope == PASSWORD_CHANGE_SCOPE:
        raise _password_change_required()
    return user


async def get_current_user_any_scope(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> AuthenticatedUser:
    """Resolve current user allowing password-change-only scope.

    Only the password-change endpoint should use this.
    """
    return await _resolve_current_user(request, db)


async def require_admin(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Gate: caller must be authenticated AND have role=admin.

    ``get_current_user`` raises 401 for unauthenticated callers; this
    wrapper adds a 403 for authenticated-but-not-admin.
    """
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "forbidden"},
        )
    return user


# Load-bearing convention: ``users.id == 1`` is the original installer
# admin (the row that ``bootstrap_admin`` mints on first startup). It
# is the only account permitted to flip cluster-global settings whose
# blast radius spans every user — currently the registration-mode
# toggle (W3.6 sub-item 3); future toggles will reuse this gate. Other
# admins can read these settings but cannot change them. The
# convention rests on the auto-increment PK starting at 1 and the
# bootstrap path always running first; ``001_auth_tables.py`` defines
# both. If we ever migrate off integer PKs or seed the table out-of-
# order, this gate must move with the convention.
ROOT_ADMIN_USER_ID = 1


async def require_root_admin(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Gate: caller must be the original installer admin (UID=1, role=admin).

    Same 401-vs-403 split as :func:`require_admin`: an unauthenticated
    caller already 401'd inside ``get_current_user``; this wrapper adds
    a 403 ``not_root_admin`` for any authenticated caller who isn't
    UID=1 with role=admin.
    """
    if user.user_id != ROOT_ADMIN_USER_ID or user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "not_root_admin"},
        )
    return user


async def require_user_role(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Gate: caller must be authenticated AND NOT be an admin.

    Self-service mutation routes (PATCH /auth/me, POST
    /auth/me/agents/{id}/revoke, POST /auth/agent/registration-code)
    are off-limits to admins under the W3.6 hard role split. Read
    routes (GET /auth/me, GET /auth/me/agents) are still allowed —
    admin needs them for the admin panel and self-introspection.
    """
    if user.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "admin_self_service_disabled"},
        )
    return user


async def get_current_agent(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> AuthenticatedAgent:
    """Resolve the bearer token as an agent api_token (not a JWT)."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise _unauthorized()
    token = auth[7:].strip()
    if not token:
        raise _unauthorized()

    row = (
        await db.execute(
            select(AgentRegistration).where(
                AgentRegistration.api_token_hash == hash_api_token(token),
                AgentRegistration.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise _unauthorized()

    return AuthenticatedAgent(
        agent_id=row.id,
        user_id=row.user_id,
        machine_name=row.machine_name,
        client_version=row.client_version,
    )
