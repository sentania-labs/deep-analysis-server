"""Request / response Pydantic models for the auth service."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


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


class MeResponse(BaseModel):
    user_id: int
    email: str
    role: str
    must_change_password: bool


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
