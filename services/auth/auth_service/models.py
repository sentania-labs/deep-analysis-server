"""SQLAlchemy models for the auth service.

All tables live in the `auth` schema (created by the root Alembic head).
This module is the target_metadata source for the auth service's own
Alembic head (services/auth/alembic/).

Design notes
------------
- Email uniqueness is enforced by a functional unique index on
  lower(email) rather than the `citext` type — avoids a cluster-wide
  extension dependency for a single column.
- `updated_at` has a server default on INSERT only. App code is
  responsible for refreshing it on UPDATE for now; we'll revisit if a
  trigger proves worth the complexity.
- Secrets (password_hash, refresh_token_hash, api_token_hash) are
  stored at rest only — never plaintext.
- `sessions.ip` is String (TEXT) rather than PostgreSQL INET for ORM
  simplicity; IPv4+IPv6 presentation strings fit comfortably.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

metadata = MetaData(schema="auth")


class Base(DeclarativeBase):
    metadata = metadata


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, server_default="user")
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),
        Index("ix_users_email_lower", func.lower(email), unique=True),
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("refresh_token_hash", name="uq_sessions_refresh_token_hash"),
        Index("ix_sessions_user_id_expires_at", "user_id", "expires_at"),
    )


class AgentRegistration(Base):
    __tablename__ = "agent_registrations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    machine_name: Mapped[str] = mapped_column(String(255), nullable=False)
    api_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    client_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("api_token_hash", name="uq_agent_registrations_api_token_hash"),
        Index("ix_agent_registrations_user_id", "user_id"),
    )
