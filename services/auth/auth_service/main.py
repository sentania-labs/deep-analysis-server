import contextlib
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from redis.asyncio import Redis
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service import models as _models  # noqa: F401 — ensure Base.metadata loaded
from auth_service.bootstrap import bootstrap_admin
from auth_service.db import get_session, get_sessionmaker
from auth_service.deps import (
    PASSWORD_CHANGE_SCOPE,
    AuthenticatedAgent,
    AuthenticatedUser,
    get_current_agent,
    get_current_user,
    get_current_user_any_scope,
    require_user_role,
)
from auth_service.jwt_issue import (
    hash_refresh_token,
    issue_access_token,
    issue_refresh_token,
)
from auth_service.models import AgentRegistration, InviteToken, ServerSetting, User
from auth_service.models import Session as SessionRow
from auth_service.passwords import hash_password, verify_password
from auth_service.registration import (
    consume_registration_code,
    generate_api_token,
    generate_registration_code,
    hash_api_token,
    hash_invite_token,
    store_registration_code,
)
from auth_service.schemas import (
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentListView,
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentRegisterWithCredentialsRequest,
    AgentRegistrationCodeResponse,
    AgentView,
    LoginRequest,
    MeResponse,
    PasswordChangeRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
    UpdateMeRequest,
    UpdateMeResponse,
)
from auth_service.settings import get_settings
from common.logging import configure_logging
from common.metrics import mount_metrics

SERVICE_NAME = "auth"
configure_logging(SERVICE_NAME)


_redis_client: Redis | None = None


def _get_or_create_redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        from redis.asyncio import from_url as redis_from_url

        _redis_client = redis_from_url(get_settings().redis_url)
    return _redis_client


def reset_redis() -> None:
    """Test hook: clear the cached Redis client after env changes."""
    global _redis_client
    _redis_client = None


_log = logging.getLogger("auth.main")


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    try:
        sm = get_sessionmaker()
        async with sm() as session:
            await bootstrap_admin(session, get_settings())
    except Exception as exc:  # noqa: BLE001 — don't crash startup on bootstrap issues
        _log.exception("admin bootstrap failed: %s", exc)
    yield


app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}", lifespan=lifespan)
mount_metrics(app, SERVICE_NAME)

from auth_service import admin  # noqa: E402
from auth_service.admin import router as _admin_router  # noqa: E402

# TODO(W7): per-admin-IP rate limit on mutation endpoints — deferred to gateway phase.
app.include_router(_admin_router)


_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"error": "invalid_credentials"},
)
_INVALID_REGISTRATION_CODE = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"error": "invalid_registration_code"},
)

# Agents call POST /auth/agent/heartbeat every 5 min — see docs/agent-protocol.md.
_REGISTRATION_CODE_TTL_SECONDS = 600


async def get_redis() -> Redis:
    return _get_or_create_redis()


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return None


@app.get("/healthz")
@app.get("/auth/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/auth/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> TokenResponse:
    # Rate limiting deferred to W7 gateway.
    # Body carries a plaintext password — any unhandled exception escaping
    # this handler could be logged with the request body by FastAPI/uvicorn,
    # leaking the password. Catch broadly and re-raise a sanitized 500.
    try:
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

        if user.must_change_password:
            access = issue_access_token(
                user.id,
                user.role,
                session_row.id,
                scope=PASSWORD_CHANGE_SCOPE,
                override_ttl_seconds=settings.password_change_token_ttl_seconds,
                email=user.email,
            )
            expires_in = settings.password_change_token_ttl_seconds
        else:
            access = issue_access_token(
                user.id,
                user.role,
                session_row.id,
                email=user.email,
                mtgo_usernames=user.mtgo_usernames,
            )
            expires_in = settings.access_token_ttl_seconds

        return TokenResponse(
            access_token=access,
            refresh_token=refresh_token,
            expires_in=expires_in,
            must_change_password=user.must_change_password,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — sanitize before re-raising
        _log.error(
            "auth.login.error",
            extra={"email": body.email, "exc_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        ) from None


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

    access = issue_access_token(
        user.id,
        user.role,
        new_session.id,
        email=user.email,
        mtgo_usernames=user.mtgo_usernames,
    )
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
async def me(
    user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
) -> MeResponse:
    row = (await db.execute(select(User).where(User.id == user.user_id))).scalar_one_or_none()
    return MeResponse(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        must_change_password=user.must_change_password,
        mtgo_usernames=row.mtgo_usernames if row else None,
    )


_ME_AGENTS_MAX_LIMIT = 200


@app.patch("/auth/me", response_model=UpdateMeResponse)
async def update_me(
    body: UpdateMeRequest,
    caller: AuthenticatedUser = Depends(require_user_role),
    db: AsyncSession = Depends(get_session),
) -> UpdateMeResponse:
    user = (await db.execute(select(User).where(User.id == caller.user_id))).scalar_one_or_none()
    if user is None or user.disabled:
        raise _INVALID_CREDENTIALS

    if body.email is not None:
        new_email = body.email.strip().lower()
        if not new_email:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "invalid_email"},
            )
        if new_email != user.email.lower():
            clash = (
                await db.execute(
                    select(User).where(
                        func.lower(User.email) == new_email,
                        User.id != user.id,
                    )
                )
            ).scalar_one_or_none()
            if clash is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={"error": "email_already_exists"},
                )
        user.email = new_email

    if body.mtgo_usernames is not None:
        cleaned = [n.strip() for n in body.mtgo_usernames if n.strip()]
        user.mtgo_usernames = cleaned or None

    user.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(user)

    # Email and mtgo_usernames are JWT claims; the caller's existing
    # token is now stale.  Mint a fresh access token bound to the same
    # session_id so the web layer can rotate the cookie without forcing
    # a re-login.
    settings = get_settings()
    fresh_access = issue_access_token(
        user.id,
        user.role,
        caller.session_id,
        email=user.email,
        mtgo_usernames=user.mtgo_usernames,
    )

    _log.info("auth.me.updated", extra={"user_id": user.id})
    return UpdateMeResponse(
        user_id=user.id,
        email=user.email,
        role=user.role,
        must_change_password=user.must_change_password,
        mtgo_usernames=user.mtgo_usernames,
        access_token=fresh_access,
        expires_in=settings.access_token_ttl_seconds,
    )


@app.get("/auth/me/agents", response_model=AgentListView)
async def list_my_agents(
    limit: int = Query(50, ge=1, le=_ME_AGENTS_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    caller: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
) -> AgentListView:
    total = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AgentRegistration)
                .where(AgentRegistration.user_id == caller.user_id)
            )
        ).scalar_one()
    )
    rows = (
        (
            await db.execute(
                select(AgentRegistration)
                .where(AgentRegistration.user_id == caller.user_id)
                .order_by(AgentRegistration.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    # Cross-schema read: count parsed matches *per agent* by joining
    # through ingest.user_uploads so each row shows only the matches
    # that were uploaded by that specific agent.
    agent_ids = [a.id for a in rows]
    parsed_counts: dict[str, int] = {}
    if agent_ids:
        pc_rows = (
            await db.execute(
                text(
                    "SELECT u.agent_registration_id, COUNT(DISTINCT m.id) AS cnt"
                    " FROM parser.matches m"
                    " JOIN ingest.user_uploads u"
                    "   ON u.sha256 = m.sha256 AND u.user_id = m.user_id"
                    " WHERE u.agent_registration_id = ANY(:aids)"
                    " GROUP BY u.agent_registration_id"
                ),
                {"aids": [str(a) for a in agent_ids]},
            )
        ).all()
        parsed_counts = {str(r[0]): int(r[1]) for r in pc_rows}

    agents = [
        AgentView(
            agent_id=a.id,
            user_id=a.user_id,
            user_email=caller.email,
            machine_name=a.machine_name,
            client_version=a.client_version,
            local_file_count=a.local_file_count,
            parsed_count=parsed_counts.get(str(a.id), 0),
            created_at=a.created_at,
            last_seen_at=a.last_seen_at,
            revoked_at=a.revoked_at,
        )
        for a in rows
    ]
    return AgentListView(agents=agents, total=total)


@app.post("/auth/me/agents/{agent_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_my_agent(
    agent_id: uuid.UUID,
    caller: AuthenticatedUser = Depends(require_user_role),
    db: AsyncSession = Depends(get_session),
) -> Response:
    agent = (
        await db.execute(select(AgentRegistration).where(AgentRegistration.id == agent_id))
    ).scalar_one_or_none()
    # Treat "doesn't exist" and "exists but isn't yours" as the same
    # 404 — the caller has no business knowing the difference, and a
    # distinct 403 lets a probe enumerate live agent IDs across the
    # tenant.
    if agent is None or agent.user_id != caller.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "agent_not_found"},
        )
    if agent.revoked_at is None:
        agent.revoked_at = datetime.now(UTC)
        await db.commit()
        _log.info("auth.me.agent_revoked", extra={"agent_id": str(agent_id)})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# TODO(policy): minimum-length of 12 is a stub; real password policy TBD.
_MIN_PASSWORD_LEN = 12


@app.post("/auth/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChangeRequest,
    caller: AuthenticatedUser = Depends(get_current_user_any_scope),
    db: AsyncSession = Depends(get_session),
) -> Response:
    if len(body.new_password) < _MIN_PASSWORD_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "weak_password"},
        )

    user = (await db.execute(select(User).where(User.id == caller.user_id))).scalar_one_or_none()
    if user is None or user.disabled:
        raise _INVALID_CREDENTIALS
    if not verify_password(body.current_password, user.password_hash):
        raise _INVALID_CREDENTIALS

    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.updated_at = datetime.now(UTC)

    now = datetime.now(UTC)
    active_sessions = (
        (
            await db.execute(
                select(SessionRow).where(
                    SessionRow.user_id == user.id,
                    SessionRow.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    for s in active_sessions:
        s.revoked_at = now

    await db.commit()

    settings = get_settings()
    if user.email == "admin@local":
        secret_path = settings.initial_admin_secret_path
        try:
            if secret_path.exists():
                secret_path.unlink()
        except OSError:  # noqa: BLE001 — best-effort cleanup
            pass

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post(
    "/auth/agent/registration-code",
    response_model=AgentRegistrationCodeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def mint_registration_code(
    user: AuthenticatedUser = Depends(require_user_role),
    redis: Redis = Depends(get_redis),
) -> AgentRegistrationCodeResponse:
    # Rate limiting deferred to gateway W7.
    code = generate_registration_code()
    await store_registration_code(
        redis, code, user.user_id, ttl_seconds=_REGISTRATION_CODE_TTL_SECONDS
    )
    expires_at = datetime.now(UTC) + timedelta(seconds=_REGISTRATION_CODE_TTL_SECONDS)
    return AgentRegistrationCodeResponse(code=code, expires_at=expires_at)


@app.post(
    "/auth/agent/register",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_agent(
    body: AgentRegisterRequest,
    redis: Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_session),
) -> AgentRegisterResponse:
    user_id = await consume_registration_code(redis, body.code)
    if user_id is None:
        raise _INVALID_REGISTRATION_CODE

    # Defense-in-depth: a code minted before W3.6.1's hard role split
    # could still be live in Redis and was minted by a then-allowed
    # admin. After the split, admins are not agent owners, so reject
    # the consume rather than create an admin-owned agent row.
    owner = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if owner is None or owner.role != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "admin_cannot_register_agent"},
        )

    api_token = generate_api_token()
    now = datetime.now(UTC)
    agent = AgentRegistration(
        user_id=user_id,
        machine_name=body.machine_name,
        api_token_hash=hash_api_token(api_token),
        created_at=now,
        last_seen_at=now,
        client_version=body.client_version,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    return AgentRegisterResponse(
        agent_id=agent.id,
        api_token=api_token,
        user_id=user_id,
    )


@app.post(
    "/auth/agent/register-with-credentials",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_agent_with_credentials(
    body: AgentRegisterWithCredentialsRequest,
    redis: Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_session),
) -> AgentRegisterResponse:
    """One-step agent registration: authenticate + register in a single call.

    Accepts {email, password, agent_name, client_version}. Authenticates the
    user with the same logic as /auth/login, auto-mints a registration code,
    immediately consumes it, and returns {agent_id, api_token, user_id} —
    the same payload as the code-based flow.

    Rejects admin users (matches the role split that /auth/agent/register
    enforces at consume time). Does not create a browser session, so no
    refresh token is issued.
    """
    # Body carries a plaintext password — any unhandled exception escaping
    # this handler could be logged with the request body by FastAPI/uvicorn,
    # leaking the password. Catch broadly and re-raise a sanitized 500.
    try:
        user = (
            await db.execute(select(User).where(func.lower(User.email) == body.email.lower()))
        ).scalar_one_or_none()
        if user is None or user.disabled:
            raise _INVALID_CREDENTIALS
        if not verify_password(body.password, user.password_hash):
            raise _INVALID_CREDENTIALS

        if user.role != "user":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "admin_cannot_register_agent"},
            )

        # Mint + consume immediately. Going through the existing helpers
        # keeps this flow symmetric with the code-based one — same Redis
        # primitive, same atomic GETDEL — so a future change to either
        # flow lands in one place. The 30s TTL is paranoia padding; in
        # practice the consume happens microseconds after the store.
        code = generate_registration_code()
        await store_registration_code(redis, code, user.id, ttl_seconds=30)
        user_id = await consume_registration_code(redis, code)
        if user_id is None:
            # Implies a Redis flush or eviction within microseconds of our
            # own store — operationally exceptional, but worth surfacing
            # rather than papering over with a silent retry.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "registration_code_race"},
            )

        api_token = generate_api_token()
        now = datetime.now(UTC)
        agent = AgentRegistration(
            user_id=user_id,
            machine_name=body.agent_name,
            api_token_hash=hash_api_token(api_token),
            created_at=now,
            last_seen_at=now,
            client_version=body.client_version,
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)

        _log.info(
            "auth.agent.register_with_credentials.success",
            extra={"agent_id": str(agent.id), "user_id": user_id},
        )
        return AgentRegisterResponse(
            agent_id=agent.id,
            api_token=api_token,
            user_id=user_id,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — sanitize before re-raising
        _log.error(
            "auth.agent.register_with_credentials.error",
            extra={"email": body.email, "exc_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "internal_error"},
        ) from None


# ---------------------------------------------------------------------------
# Public user registration — W3.6 sub-item 4
# ---------------------------------------------------------------------------


_REGISTRATION_MODE_KEY = "registration_mode"


async def _read_registration_mode(db: AsyncSession) -> str:
    row = (
        await db.execute(select(ServerSetting).where(ServerSetting.key == _REGISTRATION_MODE_KEY))
    ).scalar_one_or_none()
    if row is None:
        # Migration 003 seeds the row; absence means a deployment skew
        # we shouldn't paper over. 503 is the same surface admin.py uses
        # so the failure mode stays consistent.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registration_mode_unconfigured"},
        )
    mode = row.value if isinstance(row.value, str) else "invite_only"
    return mode if mode in ("open", "invite_only") else "invite_only"


@app.get("/auth/registration-mode")
async def public_registration_mode(
    db: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Public read of the current registration mode.

    The /admin/settings/registration-mode endpoint requires admin so
    audit metadata stays internal; this companion route exposes only
    the mode value so the public /register page can render the right
    copy + gate without the user being logged in. Non-sensitive — the
    same value is observable by any unauthenticated POST /auth/register.
    """
    return {"mode": await _read_registration_mode(db)}


@app.post(
    "/auth/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_session),
) -> RegisterResponse:
    """Public user registration.

    ``invite_only`` mode requires a valid token; ``open`` mode accepts
    a token if provided (and consumes it for audit) but doesn't require
    one. Email uniqueness and password complexity are enforced in both
    modes — token presence never short-circuits those checks.
    """
    mode = await _read_registration_mode(db)
    submitted_email = body.email.strip().lower()
    if not submitted_email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_email"},
        )
    if len(body.password) < _MIN_PASSWORD_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "weak_password"},
        )

    raw_token = (body.token or "").strip()

    if mode == "invite_only" and not raw_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "invite_required"},
        )

    invite: InviteToken | None = None
    if raw_token:
        # Lock the row for the duration of the transaction so two
        # concurrent /auth/register calls racing the same token can't
        # both see remaining capacity — the second waits, then sees
        # the incremented use_count and is rejected if exhausted.
        invite = (
            await db.execute(
                select(InviteToken)
                .where(InviteToken.token_hash == hash_invite_token(raw_token))
                .with_for_update()
            )
        ).scalar_one_or_none()
        now = datetime.now(UTC)
        if invite is None or invite.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "invalid_invite_token"},
            )
        # Check whether the invite has remaining uses.
        # max_uses=0 → unlimited (always allow, just check expiry above).
        # max_uses IS NULL → legacy single-use, treat as max_uses=1.
        # max_uses > 0 → normal multi-use, check use_count < max_uses.
        effective_max = invite.max_uses if invite.max_uses is not None else 1
        if effective_max > 0 and invite.use_count >= effective_max:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "invite_exhausted"},
            )

    # Email uniqueness check (case-insensitive). Done after token
    # validation so a stranger probing for taken emails can't bypass
    # the invite gate.
    clash = (
        await db.execute(select(User).where(func.lower(User.email) == submitted_email))
    ).scalar_one_or_none()
    if clash is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "email_already_exists"},
        )

    # If an invite specifies a role, the new user inherits it;
    # otherwise default to "user".
    assigned_role = invite.role if invite is not None else "user"
    user = User(
        email=submitted_email,
        password_hash=hash_password(body.password),
        role=assigned_role,
        must_change_password=False,
    )
    db.add(user)
    # Flush to get user.id before stamping the invite consumption.
    # The pre-insert SELECT above is the happy-path check, but a second
    # registration racing into the same email between SELECT and INSERT
    # will land on the unique index. Catch that and translate to 409.
    try:
        await db.flush()

        if invite is not None:
            invite.use_count += 1
            invite.used_at = datetime.now(UTC)
            invite.used_by_user_id = user.id

        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        msg = str(exc.orig if exc.orig is not None else exc).lower()
        if "ix_users_email_lower" in msg or ("unique" in msg and "email" in msg):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "email_already_taken"},
            ) from exc
        raise
    await db.refresh(user)

    _log.info("auth.register.success", extra={"user_id": user.id, "mode": mode})
    return RegisterResponse(user_id=user.id, email=user.email)


@app.post("/auth/agent/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(
    body: AgentHeartbeatRequest,
    agent: AuthenticatedAgent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_session),
) -> AgentHeartbeatResponse:
    # Agents call this every 5 min (see docs/agent-protocol.md).
    row = (
        await db.execute(select(AgentRegistration).where(AgentRegistration.id == agent.agent_id))
    ).scalar_one()
    row.last_seen_at = datetime.now(UTC)
    if body.client_version is not None:
        row.client_version = body.client_version
    if body.local_file_count is not None:
        row.local_file_count = body.local_file_count
    await db.commit()
    await db.refresh(row)

    # Cross-schema read: count uploads attributed to this user so the
    # agent can detect server-side data loss and trigger a re-sync.
    # Wrapped in try/except: the ingest schema may not be migrated yet
    # or the DB role may lack cross-schema permissions.
    try:
        upload_count = int(
            (
                await db.execute(
                    text("SELECT COUNT(*) FROM ingest.user_uploads WHERE user_id = :user_id"),
                    {"user_id": agent.user_id},
                )
            ).scalar_one()
        )
    except Exception:
        upload_count = 0

    # min_agent_version is admin-editable via /admin/settings/tunables.
    # Reads from auth.server_settings with a compiled fallback so a fresh
    # install with an empty settings table still returns a sane value.
    min_agent_version = await admin.read_min_agent_version(db)
    return AgentHeartbeatResponse(
        status="ok",
        registered_at=row.created_at,
        revoked=row.revoked_at is not None,
        upload_count=upload_count,
        min_agent_version=min_agent_version,
    )
