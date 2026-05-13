"""parser.games: add play/draw and opening hand metadata columns.

Revision ID: 011
Revises: 010
Create Date: 2026-05-13

Adds ``on_play``, ``play_first``, and ``opening_hand_sizes`` to
``parser.games`` for game state reconstruction (v0.9.0).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "games",
        sa.Column("on_play", sa.Boolean(), nullable=True),
        schema="parser",
    )
    op.add_column(
        "games",
        sa.Column("play_first", sa.String(255), nullable=True),
        schema="parser",
    )
    op.add_column(
        "games",
        sa.Column(
            "opening_hand_sizes",
            postgresql.JSONB(),
            nullable=False,
            server_default="{}",
        ),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_column("games", "opening_hand_sizes", schema="parser")
    op.drop_column("games", "play_first", schema="parser")
    op.drop_column("games", "on_play", schema="parser")
