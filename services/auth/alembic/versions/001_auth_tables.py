"""auth service head revision 001 — users, sessions, agent_registrations.

Revision ID: 001
Revises:
Create Date: 2026-04-23

Creates the three auth-owned tables in the `auth` schema. The schema
itself and the `deep_analysis_auth` role are created by the root head
(alembic/versions/001_initial_schema.py), which must run first.

pgcrypto is enabled here for gen_random_uuid(). It is intentionally NOT
dropped on downgrade — the extension is cluster-wide and other
consumers may depend on it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="user"),
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "disabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),
        schema="auth",
    )
    op.create_index(
        "ix_users_email_lower",
        "users",
        [sa.text("lower(email)")],
        unique=True,
        schema="auth",
    )

    op.create_table(
        "sessions",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["auth.users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("refresh_token_hash", name="uq_sessions_refresh_token_hash"),
        schema="auth",
    )
    op.create_index(
        "ix_sessions_user_id_expires_at",
        "sessions",
        ["user_id", "expires_at"],
        schema="auth",
    )

    op.create_table(
        "agent_registrations",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("machine_name", sa.String(length=255), nullable=False),
        sa.Column("api_token_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("client_version", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["auth.users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("api_token_hash", name="uq_agent_registrations_api_token_hash"),
        schema="auth",
    )
    op.create_index(
        "ix_agent_registrations_user_id",
        "agent_registrations",
        ["user_id"],
        schema="auth",
    )


def downgrade() -> None:
    op.drop_index("ix_agent_registrations_user_id", table_name="agent_registrations", schema="auth")
    op.drop_table("agent_registrations", schema="auth")
    op.drop_index("ix_sessions_user_id_expires_at", table_name="sessions", schema="auth")
    op.drop_table("sessions", schema="auth")
    op.drop_index("ix_users_email_lower", table_name="users", schema="auth")
    op.drop_table("users", schema="auth")
