"""parser.matches.review_reason: human-readable explanation for review holds.

Revision ID: 029
Revises: 028
Create Date: 2026-05-26

Adds a nullable ``review_reason`` TEXT column to ``parser.matches``.
When the consumer sets ``review_status = 'pending_review'``, it also
writes a concise reason string (e.g. "No game winners resolved
(3 games observed)") so admins can see WHY a match was held, not just
that it was.

Existing rows get NULL — the column is informational and existing
``pending_review`` rows work fine without a reason.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "029"
down_revision: str | None = "028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "matches",
        sa.Column("review_reason", sa.Text(), nullable=True),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_column("matches", "review_reason", schema="parser")
