"""parser.matches.review_status: holding pen for inconclusive parses.

Revision ID: 025
Revises: 024
Create Date: 2026-05-22

Adds a nullable ``review_status`` TEXT column to ``parser.matches`` plus
an index for the admin filter view and a CHECK constraint that limits
values to ``'pending_review'`` / ``'rejected'``. NULL is the normal,
user-visible state — no default — and an admin "accept" sets the column
back to NULL rather than introducing a separate state.

Rationale: under #75, partial parses (match-level winner None *and* no
game has a resolved winner) were dropped at the consumer. That hid
suspicious data but also hid it from the operator. Holding-pen rows
land here with ``review_status='pending_review'`` instead and are
surfaced on the admin matches page so a human can decide whether they
represent a real match worth keeping.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "025"
down_revision: str | None = "024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "matches",
        sa.Column("review_status", sa.Text(), nullable=True),
        schema="parser",
    )
    op.create_check_constraint(
        "ck_matches_review_status_valid",
        "matches",
        "review_status IS NULL OR review_status IN ('pending_review', 'rejected')",
        schema="parser",
    )
    op.create_index(
        "ix_matches_review_status",
        "matches",
        ["review_status"],
        schema="parser",
        postgresql_where=sa.text("review_status IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_matches_review_status",
        table_name="matches",
        schema="parser",
    )
    op.drop_constraint(
        "ck_matches_review_status_valid",
        "matches",
        type_="check",
        schema="parser",
    )
    op.drop_column("matches", "review_status", schema="parser")
