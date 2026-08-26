"""Request / response Pydantic models for the auth service."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class LoginRequest(BaseModel):
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    must_change_password: bool


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1)


class MeResponse(BaseModel):
    user_id: int
    email: str
    role: str
    must_change_password: bool
    mtgo_usernames: list[str] | None = None


class UpdateMeRequest(BaseModel):
    email: str | None = Field(default=None, min_length=1, max_length=320)
    mtgo_usernames: list[str] | None = None


class UpdateMeResponse(MeResponse):
    """PATCH /auth/me response — extends MeResponse with a refreshed
    access token. Email is part of the access-token claim set, so we
    re-mint on every successful update; the web layer rotates the
    session cookie so subsequent requests resolve the new identity.
    """

    access_token: str
    expires_in: int


class AgentRegistrationCodeResponse(BaseModel):
    code: str
    expires_at: datetime


class AgentRegisterRequest(BaseModel):
    code: str = Field(min_length=1, max_length=32)
    machine_name: str = Field(min_length=1, max_length=255)
    client_version: str = Field(min_length=1, max_length=64)


class AgentRegisterResponse(BaseModel):
    agent_id: uuid.UUID
    api_token: str
    user_id: int


class AgentHeartbeatRequest(BaseModel):
    client_version: str | None = Field(default=None, max_length=64)
    local_file_count: int | None = None


class AgentHeartbeatResponse(BaseModel):
    status: str
    registered_at: datetime
    revoked: bool
    upload_count: int = 0
    min_agent_version: str | None = None
    reingest_requested_at: datetime | None = None


class UserView(BaseModel):
    id: int
    email: str
    role: str
    disabled: bool
    must_change_password: bool
    mtgo_usernames: list[str] | None = None
    created_at: datetime
    updated_at: datetime


class UserListView(BaseModel):
    users: list[UserView]
    total: int


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1)
    role: Literal["user", "admin"] = "user"
    must_change_password: bool = True


class UpdateUserRequest(BaseModel):
    role: Literal["user", "admin"] | None = None
    disabled: bool | None = None
    must_change_password: bool | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> UpdateUserRequest:
        if self.role is None and self.disabled is None and self.must_change_password is None:
            raise ValueError("at_least_one_field_required")
        return self


class ResetPasswordResponse(BaseModel):
    temporary_password: str
    # Sessions killed as part of the reset. The caller's own session is
    # not counted when an admin resets their own password.
    revoked_sessions: int = 0


class AgentView(BaseModel):
    agent_id: uuid.UUID
    user_id: int
    user_email: str
    machine_name: str
    client_version: str | None
    local_file_count: int | None = None
    parsed_count: int | None = None
    created_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None
    reingest_requested_at: datetime | None = None


class AgentListView(BaseModel):
    agents: list[AgentView]
    total: int


class ReingestResponse(BaseModel):
    affected_count: int


class StaleCleanupResponse(BaseModel):
    revoked_count: int
    cutoff_date: str


class RotateKeyResponse(BaseModel):
    agent_id: uuid.UUID
    api_token: str


class RevokeSessionsResponse(BaseModel):
    revoked_count: int


RegistrationMode = Literal["open", "invite_only"]


class RegistrationModeView(BaseModel):
    mode: RegistrationMode
    updated_at: datetime
    updated_by_user_id: int | None


class SetRegistrationModeRequest(BaseModel):
    mode: RegistrationMode


# ---------------------------------------------------------------------------
# Invite tokens — W3.6 sub-item 4
# ---------------------------------------------------------------------------


# Caps come from the spec: 168h default (7 days), 720h max (30 days).
# Anything beyond a month would render the audit trail meaningless and
# encourage stale tokens leaking.
INVITE_TOKEN_DEFAULT_HOURS = 168
INVITE_TOKEN_MAX_HOURS = 720


class CreateInviteRequest(BaseModel):
    expires_in_hours: int = Field(
        default=INVITE_TOKEN_DEFAULT_HOURS,
        ge=1,
        le=INVITE_TOKEN_MAX_HOURS,
    )
    max_uses: int = Field(default=1, ge=0, le=10000)
    role: Literal["user", "admin"] = "user"


class CreateInviteResponse(BaseModel):
    """Response from POST /admin/invites — plaintext token shown once."""

    id: uuid.UUID
    token: str
    expires_at: datetime
    created_at: datetime
    max_uses: int
    role: str


class InviteView(BaseModel):
    id: uuid.UUID
    created_by_user_id: int | None
    created_by_email: str | None
    created_at: datetime
    expires_at: datetime
    max_uses: int
    use_count: int
    role: str


class InviteListView(BaseModel):
    invites: list[InviteView]
    total: int


class RegisterRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1)
    token: str | None = Field(default=None, max_length=128)


class RegisterResponse(BaseModel):
    user_id: int
    email: str


class AgentRegisterWithCredentialsRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, json_schema_extra={"writeOnly": True})
    agent_name: str = Field(min_length=1, max_length=255)
    client_version: str = Field(min_length=1, max_length=64)


# ---------------------------------------------------------------------------
# Admin tunables — configurable server settings
# ---------------------------------------------------------------------------


class TunablesView(BaseModel):
    """Current values of all tunables — both mutable (DB-stored) and
    read-only code constants."""

    backfill_batch_size: int
    backfill_interval_seconds: int
    scryfall_sync_interval_days: int
    mtgo_scraper_interval_hours: int
    reparse_min_version: str
    min_agent_version: str
    parser_version: str


class UpdateTunablesRequest(BaseModel):
    """Only the mutable tunables may be patched."""

    backfill_batch_size: int | None = Field(default=None, ge=10, le=1000)
    backfill_interval_seconds: int | None = Field(default=None, ge=60, le=3600)
    scryfall_sync_interval_days: int | None = Field(default=None, ge=1, le=30)
    mtgo_scraper_interval_hours: int | None = Field(default=None, ge=1, le=168)
    # Version-string tunables. Validated against a loose semver regex
    # in the admin endpoint so we can return a 400 with a field-level
    # error rather than letting Pydantic 422 the whole request.
    parser_version: str | None = Field(default=None, max_length=64)
    reparse_min_version: str | None = Field(default=None, max_length=64)
    min_agent_version: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _at_least_one(self) -> UpdateTunablesRequest:
        if all(
            v is None
            for v in (
                self.backfill_batch_size,
                self.backfill_interval_seconds,
                self.scryfall_sync_interval_days,
                self.mtgo_scraper_interval_hours,
                self.parser_version,
                self.reparse_min_version,
                self.min_agent_version,
            )
        ):
            raise ValueError("at_least_one_field_required")
        return self


# ---------------------------------------------------------------------------
# MOTD (Message of the Day) — site-wide banner
# ---------------------------------------------------------------------------


class MotdView(BaseModel):
    """Current state of the MOTD banner."""

    active: bool
    message: str | None = None
    severity: str | None = None
    expires_at: datetime | None = None
    updated_at: datetime | None = None
    updated_by_user_id: int | None = None


class SetMotdRequest(BaseModel):
    """Admin request to set or replace the active MOTD."""

    message: str = Field(min_length=1, max_length=1000)
    severity: Literal["info", "warning"] = "info"
    expires_at: str = Field(min_length=1, max_length=64)
