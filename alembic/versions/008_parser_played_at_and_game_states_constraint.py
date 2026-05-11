"""parser: add played_at to matches; widen game_states unique constraint.

Revision ID: 008
Revises: 007
Create Date: 2026-05-11

Two fixes:

1. ``parser.matches`` gains a nullable ``played_at`` column populated
   from the first binary frame's .NET timestamp during parse.  The
   dashboard previously displayed ``parsed_at`` (server-side) as the
   match date; now it will display the real match start time.

2. The ``uq_game_states_game_turn`` constraint on
   ``parser.game_states`` is widened from ``(game_id, turn_number)``
   to ``(game_id, turn_number, active_player)``.  MTGO emits two turn
   entries per turn number — one for each player's active phase — so
   the narrower constraint caused every turn-bearing match to roll back
   on the second insert.

DB-wipe authorised: no backward-compat migration needed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add played_at to parser.matches.
    op.add_column(
        "matches",
        sa.Column("played_at", sa.DateTime(timezone=True), nullable=True),
        schema="parser",
    )

    # 2. Drop the old narrow constraint and add the widened one.
    op.drop_constraint(
        "uq_game_states_game_turn",
        "game_states",
        schema="parser",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_game_states_game_turn",
        "game_states",
        ["game_id", "turn_number", "active_player"],
        schema="parser",
    )


def downgrade() -> None:
    # Reverse the constraint change.
    op.drop_constraint(
        "uq_game_states_game_turn",
        "game_states",
        schema="parser",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_game_states_game_turn",
        "game_states",
        ["game_id", "turn_number"],
        schema="parser",
    )

    # Drop played_at from parser.matches.
    op.drop_column("matches", "played_at", schema="parser")
