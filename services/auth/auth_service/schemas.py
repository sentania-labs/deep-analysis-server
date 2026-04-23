"""Request / response Pydantic models for the auth service."""

from __future__ import annotations

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
