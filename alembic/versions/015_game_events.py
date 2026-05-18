"""parser.game_events: discrete event stream per game.

Revision ID: 015
Revises: 014
Create Date: 2026-05-17

Adds the ``parser.game_events`` table that stores fine-grained game
actions (cast, play, draw, discard, exile, graveyard, damage,
life_change, mana_float) alongside the existing zone-snapshot rows in
``game_states``.  Events preserve the verb that is lost when plays and
casts are folded into a single battlefield list.

Columns:
  id          BIGSERIAL PRIMARY KEY
  game_id     UUID FK → parser.games(id) ON DELETE CASCADE
  seq         INTEGER — ordering within the game
  verb        TEXT — action type
  card_name   TEXT (nullable — anonymous draws)
  player      TEXT
  turn_number INTEGER
  source_card TEXT (nullable — e.g. source of triggered draw)

Indexes:
  ix_game_events_game_id       — fast join on game_id
  ix_game_events_game_id_turn  — turn-scoped queries
  uq_game_events_game_seq      — uniqueness within a game
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "game_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "game_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parser.games.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("verb", sa.Text, nullable=False),
        sa.Column("card_name", sa.Text, nullable=True),
        sa.Column("player", sa.Text, nullable=False),
        sa.Column("turn_number", sa.Integer, nullable=False),
        sa.Column("source_card", sa.Text, nullable=True),
        sa.UniqueConstraint("game_id", "seq", name="uq_game_events_game_seq"),
        schema="parser",
    )
    op.create_index(
        "ix_game_events_game_id",
        "game_events",
        ["game_id"],
        schema="parser",
    )
    op.create_index(
        "ix_game_events_game_id_turn",
        "game_events",
        ["game_id", "turn_number"],
        schema="parser",
    )


def downgrade() -> None:
    op.drop_index("ix_game_events_game_id_turn", table_name="game_events", schema="parser")
    op.drop_index("ix_game_events_game_id", table_name="game_events", schema="parser")
    op.drop_table("game_events", schema="parser")
