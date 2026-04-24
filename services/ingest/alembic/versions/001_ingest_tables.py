"""ingest service head revision 001 — game_log_files, user_uploads.

Revision ID: 001
Revises:
Create Date: 2026-04-24

The ingest schema is created by the root head; this migration owns
the two tables inside it. Cross-schema foreign keys to auth.users
and auth.agent_registrations rely on REFERENCES grants issued by the
root head's revision 002.
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
    op.create_table(
        "game_log_files",
        sa.Column("sha256", sa.String(length=64), primary_key=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.String(length=32), nullable=False),
        sa.Column("storage_path", sa.String(length=512), nullable=False),
        sa.Column(
            "first_uploaded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "content_type IN ('match-log', 'decklist', 'unknown')",
            name="ck_game_log_files_content_type",
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name="ck_game_log_files_size_nonneg",
        ),
        schema="ingest",
    )

    op.create_table(
        "user_uploads",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "agent_registration_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "uploaded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("original_filename", sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(
            ["sha256"],
            ["ingest.game_log_files.sha256"],
            name="fk_user_uploads_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["auth.users.id"],
            ondelete="CASCADE",
            name="fk_user_uploads_user_id",
        ),
        sa.ForeignKeyConstraint(
            ["agent_registration_id"],
            ["auth.agent_registrations.id"],
            ondelete="CASCADE",
            name="fk_user_uploads_agent_registration_id",
        ),
        schema="ingest",
    )
    op.create_index(
        "ix_user_uploads_user_uploaded_at",
        "user_uploads",
        ["user_id", "uploaded_at"],
        schema="ingest",
    )
    op.create_index(
        "ix_user_uploads_sha256",
        "user_uploads",
        ["sha256"],
        schema="ingest",
    )


def downgrade() -> None:
    op.drop_index("ix_user_uploads_sha256", table_name="user_uploads", schema="ingest")
    op.drop_index("ix_user_uploads_user_uploaded_at", table_name="user_uploads", schema="ingest")
    op.drop_table("user_uploads", schema="ingest")
    op.drop_table("game_log_files", schema="ingest")
