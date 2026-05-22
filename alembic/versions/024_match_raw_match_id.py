"""parser.matches.raw_match_id: logical-match identity from MTGO UUID.

Revision ID: 024
Revises: 023
Create Date: 2026-05-22

Adds a nullable ``raw_match_id`` TEXT column to ``parser.matches``
plus a partial unique index on ``(raw_match_id, user_id)`` so that
multiple snapshots of the same MTGO match (different sha256 because
the game-log file grows during play) collapse onto a single row.

The legacy ``(sha256, user_id)`` unique constraint is kept — it still
guarantees byte-level idempotency for rows whose ``raw_match_id`` is
NULL (very old logs or unparseable headers).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "024"
down_revision: str | None = "023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "matches",
        sa.Column("raw_match_id", sa.Text(), nullable=True),
        schema="parser",
    )
    op.create_index(
        "ix_matches_raw_match_id",
        "matches",
        ["raw_match_id"],
        schema="parser",
    )
    # Partial unique index: only enforced when raw_match_id is present.
    # Legacy NULL rows are unaffected and keep relying on (sha256, user_id).
    op.create_index(
        "uq_matches_raw_match_id_user",
        "matches",
        ["raw_match_id", "user_id"],
        unique=True,
        schema="parser",
        postgresql_where=sa.text("raw_match_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_matches_raw_match_id_user",
        table_name="matches",
        schema="parser",
    )
    op.drop_index(
        "ix_matches_raw_match_id",
        table_name="matches",
        schema="parser",
    )
    op.drop_column("matches", "raw_match_id", schema="parser")
