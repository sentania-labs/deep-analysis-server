"""auth.agent_registrations.reingest_requested_at: admin-initiated reingest signal.

Revision ID: 010
Revises: 009
Create Date: 2026-05-26

Adds a nullable ``reingest_requested_at`` TIMESTAMPTZ column to
``auth.agent_registrations``. When an admin stamps this column via the
new reingest endpoints, the agent sees it in its next heartbeat response
and clears its local upload history to re-send all files.

Existing rows get NULL — no reingest pending.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_registrations",
        sa.Column("reingest_requested_at", sa.DateTime(timezone=True), nullable=True),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("agent_registrations", "reingest_requested_at", schema="auth")
