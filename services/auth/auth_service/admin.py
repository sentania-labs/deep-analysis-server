"""Admin endpoints — user + agent management.

All endpoints are gated by :func:`require_admin`. Mutation endpoints
include guards against accidental lockout (cannot disable/delete the
last admin; cannot disable/delete yourself).
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.db import get_session
from auth_service.deps import AuthenticatedUser, require_admin, require_root_admin
from auth_service.models import AgentRegistration, ServerSetting, User
from auth_service.models import Session as SessionRow
from auth_service.passwords import hash_password
from auth_service.schemas import (
    AgentListView,
    AgentView,
    CreateUserRequest,
    RegistrationModeView,
    ResetPasswordResponse,
    RevokeSessionsResponse,
    SetRegistrationModeRequest,
    StaleCleanupResponse,
    UpdateUserRequest,
    UserListView,
    UserView,
)

# TODO(W7): per-admin-IP rate limit on mutation endpoints — deferred to gateway phase.

router = APIRouter(prefix="/admin", tags=["admin"])

_MAX_LIMIT = 200


def _user_view(u: User) -> UserView:
    return UserView(
        id=u.id,
        email=u.email,
        role=u.role,
        disabled=u.disabled,
        must_change_password=u.must_change_password,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


async def _active_admin_count(db: AsyncSession) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(User)
                .where(User.role == "admin", User.disabled.is_(False))
            )
        ).scalar_one()
    )


def _error(status_code: int, code: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": code})


@router.get("/users", response_model=UserListView)
async def list_users(
    limit: int = Query(50, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> UserListView:
    total = int((await db.execute(select(func.count()).select_from(User))).scalar_one())
    rows = (
        (await db.execute(select(User).order_by(User.id).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return UserListView(users=[_user_view(u) for u in rows], total=total)


@router.post("/users", response_model=UserView, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> UserView:
    existing = (
        await db.execute(select(User).where(func.lower(User.email) == body.email.lower()))
    ).scalar_one_or_none()
    if existing is not None:
        raise _error(status.HTTP_409_CONFLICT, "email_already_exists")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        must_change_password=body.must_change_password,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return _user_view(user)


@router.patch("/users/{user_id}", response_model=UserView)
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> UserView:
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target is None:
        raise _error(status.HTTP_404_NOT_FOUND, "user_not_found")

    if body.disabled is True and admin.user_id == target.id:
        raise _error(status.HTTP_400_BAD_REQUEST, "cannot_disable_self")

    demoting = body.role == "user" and target.role == "admin" and not target.disabled
    if demoting and await _active_admin_count(db) <= 1:
        raise _error(status.HTTP_400_BAD_REQUEST, "cannot_demote_last_admin")

    if body.role is not None:
        target.role = body.role
    if body.disabled is not None:
        target.disabled = body.disabled
    if body.must_change_password is not None:
        target.must_change_password = body.must_change_password
    target.updated_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(target)
    return _user_view(target)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> Response:
    if admin.user_id == user_id:
        raise _error(status.HTTP_400_BAD_REQUEST, "cannot_delete_self")

    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target is None:
        raise _error(status.HTTP_404_NOT_FOUND, "user_not_found")

    if target.role == "admin" and not target.disabled and await _active_admin_count(db) <= 1:
        raise _error(status.HTTP_400_BAD_REQUEST, "cannot_delete_last_admin")

    await db.delete(target)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users/{user_id}/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    user_id: int,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> ResetPasswordResponse:
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target is None:
        raise _error(status.HTTP_404_NOT_FOUND, "user_not_found")

    temp = secrets.token_urlsafe(18)
    target.password_hash = hash_password(temp)
    target.must_change_password = True
    target.updated_at = datetime.now(UTC)
    await db.commit()
    return ResetPasswordResponse(temporary_password=temp)


@router.post("/users/{user_id}/revoke-sessions", response_model=RevokeSessionsResponse)
async def revoke_sessions(
    user_id: int,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> RevokeSessionsResponse:
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target is None:
        raise _error(status.HTTP_404_NOT_FOUND, "user_not_found")

    rows = (
        (
            await db.execute(
                select(SessionRow).where(
                    SessionRow.user_id == user_id,
                    SessionRow.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for r in rows:
        r.revoked_at = now
    await db.commit()
    return RevokeSessionsResponse(revoked_count=len(rows))


@router.get("/agents", response_model=AgentListView)
async def list_agents(
    limit: int = Query(50, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> AgentListView:
    total = int(
        (await db.execute(select(func.count()).select_from(AgentRegistration))).scalar_one()
    )
    rows = (
        await db.execute(
            select(AgentRegistration, User.email)
            .join(User, User.id == AgentRegistration.user_id)
            .order_by(AgentRegistration.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    agents = [
        AgentView(
            agent_id=a.id,
            user_id=a.user_id,
            user_email=email,
            machine_name=a.machine_name,
            client_version=a.client_version,
            created_at=a.created_at,
            last_seen_at=a.last_seen_at,
            revoked_at=a.revoked_at,
        )
        for a, email in rows
    ]
    return AgentListView(agents=agents, total=total)


@router.post("/agents/{agent_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent(
    agent_id: uuid.UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> Response:
    agent = (
        await db.execute(select(AgentRegistration).where(AgentRegistration.id == agent_id))
    ).scalar_one_or_none()
    if agent is None:
        raise _error(status.HTTP_404_NOT_FOUND, "agent_not_found")
    if agent.revoked_at is None:
        agent.revoked_at = datetime.now(UTC)
        await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Server settings — W3.6.3 (registration mode toggle, UID=1 only)
# ---------------------------------------------------------------------------


_REGISTRATION_MODE_KEY = "registration_mode"


def _registration_mode_view(row: ServerSetting) -> RegistrationModeView:
    # Migration 003 seeds value=`"invite_only"` (a JSON string). Fall
    # through to ``invite_only`` if a future migration ever stores a
    # malformed value — never let an unparseable row brick the toggle.
    mode = row.value if isinstance(row.value, str) else "invite_only"
    if mode not in ("open", "invite_only"):
        mode = "invite_only"
    return RegistrationModeView(
        mode=mode,
        updated_at=row.updated_at,
        updated_by_user_id=row.updated_by_user_id,
    )


@router.get("/settings/registration-mode", response_model=RegistrationModeView)
async def get_registration_mode(
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> RegistrationModeView:
    """Read the current registration mode. Any admin may read."""
    row = (
        await db.execute(select(ServerSetting).where(ServerSetting.key == _REGISTRATION_MODE_KEY))
    ).scalar_one_or_none()
    if row is None:
        # Migration 003 seeds the row, so absence means a migration was
        # rolled back or skipped. Surface 503 so ops sees it; lying with
        # a synthesized default would mask the underlying drift.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registration_mode_unconfigured"},
        )
    return _registration_mode_view(row)


@router.put("/settings/registration-mode", response_model=RegistrationModeView)
async def set_registration_mode(
    body: SetRegistrationModeRequest,
    admin: AuthenticatedUser = Depends(require_root_admin),
    db: AsyncSession = Depends(get_session),
) -> RegistrationModeView:
    """Flip the registration mode. Only the original installer admin
    (UID=1, role=admin) may write — see :func:`require_root_admin`."""
    row = (
        await db.execute(select(ServerSetting).where(ServerSetting.key == _REGISTRATION_MODE_KEY))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        row = ServerSetting(
            key=_REGISTRATION_MODE_KEY,
            value=body.mode,
            updated_at=now,
            updated_by_user_id=admin.user_id,
        )
        db.add(row)
    else:
        row.value = body.mode
        row.updated_at = now
        row.updated_by_user_id = admin.user_id
    await db.commit()
    await db.refresh(row)
    return _registration_mode_view(row)


@router.post("/agents/cleanup-stale", response_model=StaleCleanupResponse)
async def cleanup_stale_agents(
    stale_days: int = Query(90, ge=1, le=3650),
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> StaleCleanupResponse:
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=stale_days)
    rows = (
        (
            await db.execute(
                select(AgentRegistration).where(
                    AgentRegistration.revoked_at.is_(None),
                    AgentRegistration.last_seen_at.is_not(None),
                    AgentRegistration.last_seen_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    for r in rows:
        r.revoked_at = now
    await db.commit()
    return StaleCleanupResponse(revoked_count=len(rows), cutoff_date=cutoff.isoformat())
