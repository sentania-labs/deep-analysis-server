from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service import models as _models  # noqa: F401 — ensure Base.metadata loaded
from auth_service.db import get_session
from auth_service.deps import AuthenticatedUser, get_current_user
from auth_service.jwt_issue import (
    hash_refresh_token,
    issue_access_token,
    issue_refresh_token,
)
from auth_service.models import Session as SessionRow
from auth_service.models import User
from auth_service.passwords import verify_password
from auth_service.schemas import (
    LoginRequest,
    MeResponse,
    RefreshRequest,
    TokenResponse,
)
from auth_service.settings import get_settings
from common.logging import configure_logging
from common.metrics import mount_metrics

SERVICE_NAME = "auth"
configure_logging(SERVICE_NAME)
app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}")
mount_metrics(app, SERVICE_NAME)


_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"error": "invalid_credentials"},
)


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return None


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/auth/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    # Rate limiting deferred to W7 gateway.
    settings = get_settings()
    user = (
        await db.execute(select(User).where(func.lower(User.email) == body.email.lower()))
    ).scalar_one_or_none()
    if user is None or user.disabled:
        raise _INVALID_CREDENTIALS
    if not verify_password(body.password, user.password_hash):
        raise _INVALID_CREDENTIALS

    refresh_token = issue_refresh_token()
    now = datetime.now(UTC)
    session_row = SessionRow(
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        issued_at=now,
        expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
        user_agent=(request.headers.get("user-agent") or None),
        ip=_client_ip(request),
    )
    db.add(session_row)
    await db.commit()
    await db.refresh(session_row)

    access = issue_access_token(user.id, user.role, session_row.id)
    return TokenResponse(
        access_token=access,
        refresh_token=refresh_token,
        expires_in=settings.access_token_ttl_seconds,
        must_change_password=user.must_change_password,
    )


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    settings = get_settings()
    token_hash = hash_refresh_token(body.refresh_token)
    row = (
        await db.execute(
            select(SessionRow, User)
            .join(User, User.id == SessionRow.user_id)
            .where(SessionRow.refresh_token_hash == token_hash)
        )
    ).first()
    if row is None:
        raise _INVALID_CREDENTIALS
    old_session, user = row

    now = datetime.now(UTC)
    if old_session.revoked_at is not None or old_session.expires_at <= now:
        raise _INVALID_CREDENTIALS
    if user.disabled:
        raise _INVALID_CREDENTIALS

    old_session.revoked_at = now

    new_refresh = issue_refresh_token()
    new_session = SessionRow(
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(new_refresh),
        issued_at=now,
        expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
        user_agent=(request.headers.get("user-agent") or None),
        ip=_client_ip(request),
    )
    db.add(new_session)
    await db.commit()
    await db.refresh(new_session)

    access = issue_access_token(user.id, user.role, new_session.id)
    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=settings.access_token_ttl_seconds,
        must_change_password=user.must_change_password,
    )


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> Response:
    # Idempotent — always 204. Swallow invalid tokens silently.
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            try:
                from auth_service.deps import get_verifier  # local import avoids cycle

                claims = get_verifier().verify(token)
                sid = claims.get("sid")
                if sid:
                    import uuid as _uuid

                    try:
                        session_id = _uuid.UUID(sid)
                    except ValueError:
                        session_id = None
                    if session_id is not None:
                        session_row = (
                            await db.execute(select(SessionRow).where(SessionRow.id == session_id))
                        ).scalar_one_or_none()
                        if session_row is not None and session_row.revoked_at is None:
                            session_row.revoked_at = datetime.now(UTC)
                            await db.commit()
            except Exception:  # noqa: BLE001 — logout is best-effort + idempotent
                pass
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/auth/me", response_model=MeResponse)
async def me(user: AuthenticatedUser = Depends(get_current_user)) -> MeResponse:
    return MeResponse(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        must_change_password=user.must_change_password,
    )
