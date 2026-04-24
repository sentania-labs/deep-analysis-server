"""FastAPI dependencies for the ingest service.

``get_current_agent`` resolves a bearer agent API token by querying
``auth.agent_registrations`` directly via SQL text — the ingest role
has SELECT on the auth schema (root Alembic 001). The ingest service
intentionally does not import from ``auth_service`` to keep the
service boundary clean.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.agent_auth import AuthenticatedAgent
from common.token_utils import hash_api_token
from ingest_service.db import get_session


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized"},
    )


def _extract_bearer(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise _unauthorized()
    token = auth[7:].strip()
    if not token:
        raise _unauthorized()
    return token


async def get_current_agent(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> AuthenticatedAgent:
    token = _extract_bearer(request)
    row = (
        await db.execute(
            text(
                "SELECT id, user_id, machine_name, client_version "
                "FROM auth.agent_registrations "
                "WHERE api_token_hash = :h AND revoked_at IS NULL"
            ),
            {"h": hash_api_token(token)},
        )
    ).one_or_none()
    if row is None:
        raise _unauthorized()

    agent_id, user_id, machine_name, client_version = row
    if not isinstance(agent_id, uuid.UUID):
        agent_id = uuid.UUID(str(agent_id))
    return AuthenticatedAgent(
        agent_id=agent_id,
        user_id=int(user_id),
        machine_name=str(machine_name),
        client_version=(None if client_version is None else str(client_version)),
    )
