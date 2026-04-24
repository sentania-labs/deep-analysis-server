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
from auth_service.registration import hash_api_token
from auth_service.settings import get_settings
from common.jwt_verify import InvalidTokenError, JWTVerifier


@dataclass
class AuthenticatedUser:
    user_id: int
    email: str
    role: str
    session_id: uuid.UUID
    must_change_password: bool


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


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
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

    return AuthenticatedUser(
        user_id=user.id,
        email=user.email,
        role=user.role,
        session_id=session_row.id,
        must_change_password=user.must_change_password,
    )


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


@dataclass
class AuthenticatedAgent:
    agent_id: uuid.UUID
    user_id: int
    machine_name: str
    client_version: str | None


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
