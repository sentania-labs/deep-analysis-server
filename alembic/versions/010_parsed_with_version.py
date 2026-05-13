"""parser.matches: add parsed_with_version column for versioned reparse.

Revision ID: 010
Revises: 009
Create Date: 2026-05-13

Tracks which parser version produced each match row so the backfill
scanner can detect stale parses and queue them for re-processing.
"""

import sqlalchemy as sa

from alembic import op

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "matches",
        sa.Column("parsed_with_version", sa.Text(), nullable=True),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_column("matches", "parsed_with_version", schema="parser")
