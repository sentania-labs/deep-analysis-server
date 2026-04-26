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


class UpdateMeRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)


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


class AgentHeartbeatResponse(BaseModel):
    status: str
    registered_at: datetime
    revoked: bool


class UserView(BaseModel):
    id: int
    email: str
    role: str
    disabled: bool
    must_change_password: bool
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


class AgentView(BaseModel):
    agent_id: uuid.UUID
    user_id: int
    user_email: str
    machine_name: str
    client_version: str | None
    created_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None


class AgentListView(BaseModel):
    agents: list[AgentView]
    total: int


class StaleCleanupResponse(BaseModel):
    revoked_count: int
    cutoff_date: str


class RevokeSessionsResponse(BaseModel):
    revoked_count: int
