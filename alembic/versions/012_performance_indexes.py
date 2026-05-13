"""Add performance indexes for common query patterns.

Revision ID: 012
Revises: 011
Create Date: 2026-05-13

Adds composite indexes that cover the most common dashboard and
background-worker query patterns:

- matches(user_id, played_at) — dashboard date-range filtering
- matches(user_id, format) — dashboard format filter
- matches(parsed_with_version) — backfill scanner stale-match query
- game_states(game_id, turn_number) — turn viewer load order
"""

from alembic import op

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_matches_user_id_played_at",
        "matches",
        ["user_id", "played_at"],
        schema="parser",
    )
    op.create_index(
        "ix_matches_user_id_format",
        "matches",
        ["user_id", "format"],
        schema="parser",
    )
    op.create_index(
        "ix_matches_parsed_with_version",
        "matches",
        ["parsed_with_version"],
        schema="parser",
    )
    op.create_index(
        "ix_game_states_game_id_turn",
        "game_states",
        ["game_id", "turn_number"],
        schema="parser",
    )


def downgrade() -> None:
    op.drop_index("ix_game_states_game_id_turn", table_name="game_states", schema="parser")
    op.drop_index("ix_matches_parsed_with_version", table_name="matches", schema="parser")
    op.drop_index("ix_matches_user_id_format", table_name="matches", schema="parser")
    op.drop_index("ix_matches_user_id_played_at", table_name="matches", schema="parser")
