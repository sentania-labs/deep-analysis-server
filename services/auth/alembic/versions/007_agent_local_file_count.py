"""auth.agent_registrations: add local_file_count column.

Revision ID: 007
Revises: 006
Create Date: 2026-05-12

Stores the number of match log files the agent has discovered locally.
Used by the dashboard to compare local vs parsed counts and surface
a "force reparse" action when a mismatch is detected.
"""

import sqlalchemy as sa

from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_registrations",
        sa.Column("local_file_count", sa.Integer(), nullable=True),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("agent_registrations", "local_file_count", schema="auth")
