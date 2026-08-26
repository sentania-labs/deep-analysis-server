"""Add ``agent_classification`` to ingest.user_uploads.

Revision ID: 004
Revises: 003
Create Date: 2026-08-26

The agent already ships an ``agent_classification`` form field
("complete" or "inconclusive") derived from a tail scan of the match
log at capture time. Persisting it lets the parser backfill replay the
verdict on reparse, when the original ``file.ingested`` event is long
gone.

Nullable on purpose: agents older than the field send nothing, and
every existing row backfills as NULL.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user_uploads",
        sa.Column("agent_classification", sa.String(length=16), nullable=True),
        schema="ingest",
    )
    op.create_check_constraint(
        "ck_user_uploads_agent_classification",
        "user_uploads",
        "agent_classification IS NULL OR agent_classification IN ('complete', 'inconclusive')",
        schema="ingest",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_user_uploads_agent_classification",
        "user_uploads",
        schema="ingest",
    )
    op.drop_column("user_uploads", "agent_classification", schema="ingest")
