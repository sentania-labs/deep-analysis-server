"""parser.game_players: per-game player rows with hero/opponent flags.

Revision ID: 017
Revises: 016
Create Date: 2026-05-17

Adds the ``parser.game_players`` table that stores one row per player
per game with hero/opponent identification (``is_local``), play/draw
choice (``on_play``), and mulligan count.  This denormalises data that
was previously resolved at query time by triplicated helpers in the
analytics service.

Columns:
  id              BIGSERIAL PRIMARY KEY
  game_id         UUID FK -> parser.games(id) ON DELETE CASCADE
  player_name     TEXT NOT NULL
  is_local        BOOLEAN (true = hero, false = opponent, null = unknown)
  on_play         BOOLEAN (true = this player chose to play first)
  mulligan_count  INTEGER (7 - opening_hand_size for this player)

Constraints:
  uq_game_players_game_player  UNIQUE (game_id, player_name)

Indexes:
  ix_game_players_game_id      fast join on game_id
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "game_players",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "game_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parser.games.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("player_name", sa.Text, nullable=False),
        sa.Column("is_local", sa.Boolean, nullable=True),
        sa.Column("on_play", sa.Boolean, nullable=True),
        sa.Column("mulligan_count", sa.Integer, nullable=True),
        sa.UniqueConstraint("game_id", "player_name", name="uq_game_players_game_player"),
        schema="parser",
    )
    op.create_index(
        "ix_game_players_game_id",
        "game_players",
        ["game_id"],
        schema="parser",
    )


def downgrade() -> None:
    op.drop_index("ix_game_players_game_id", table_name="game_players", schema="parser")
    op.drop_table("game_players", schema="parser")
