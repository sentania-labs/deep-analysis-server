"""analytics.card_game_stats: add first_cast_turn column.

Revision ID: 027
Revises: 026
Create Date: 2026-05-24

Adds ``first_cast_turn INTEGER NULL`` so the materialized path can serve
``avg_cast_turn`` from a simple ``AVG(first_cast_turn) FILTER (...)``
aggregate. Previously the materialized path hard-coded the field to
``None``; sorting by Avg Cast Turn was a no-op for users with enough
data to hit the materialized branch.

No backfill in the migration. Existing rows stay NULL until they are
re-derived by the reparse pipeline (per-user via ``/profile`` or bulk
via admin reparse).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "027"
down_revision: str | None = "026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "card_game_stats",
        sa.Column("first_cast_turn", sa.Integer(), nullable=True),
        schema="analytics",
    )


def downgrade() -> None:
    op.drop_column("card_game_stats", "first_cast_turn", schema="analytics")
