"""parser schema tables — matches, games, game_states.

Revision ID: 003
Revises: 002
Create Date: 2026-05-09

The parser schema is created by revision 001; this migration owns
the three tables inside it.

Cross-schema references (``sha256`` → ``ingest.game_log_files``,
``user_id`` → ``auth.users``) are intentionally stored as plain
columns rather than foreign keys: the root alembic head runs before
auth and ingest service heads, so the target tables don't exist
yet at table-create time. Values are still trustworthy because they
originate from the ``file.ingested`` event published by the ingest
service after a successful upload commit.

The ``pgcrypto`` extension is enabled to back ``gen_random_uuid()``
for the surrogate match/game IDs.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    op.create_table(
        "matches",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("format", sa.String(length=64), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=True),
        sa.Column(
            "players",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("match_result", sa.String(length=64), nullable=True),
        sa.Column("winner", sa.String(length=255), nullable=True),
        sa.Column("game_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "parsed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("sha256", "user_id", name="uq_matches_sha256_user"),
        schema="parser",
    )
    op.create_index(
        "ix_matches_user_id_parsed_at",
        "matches",
        ["user_id", "parsed_at"],
        schema="parser",
    )
    op.create_index(
        "ix_matches_sha256",
        "matches",
        ["sha256"],
        schema="parser",
    )

    op.create_table(
        "games",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "match_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("game_number", sa.Integer(), nullable=False),
        sa.Column("winner", sa.String(length=255), nullable=True),
        sa.Column("result", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["match_id"],
            ["parser.matches.id"],
            ondelete="CASCADE",
            name="fk_games_match_id",
        ),
        sa.UniqueConstraint("match_id", "game_number", name="uq_games_match_game_number"),
        schema="parser",
    )
    op.create_index(
        "ix_games_match_id",
        "games",
        ["match_id"],
        schema="parser",
    )

    op.create_table(
        "game_states",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "game_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("turn_number", sa.Integer(), nullable=False),
        sa.Column("active_player", sa.String(length=255), nullable=True),
        sa.Column(
            "player_states",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "stack",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.ForeignKeyConstraint(
            ["game_id"],
            ["parser.games.id"],
            ondelete="CASCADE",
            name="fk_game_states_game_id",
        ),
        sa.UniqueConstraint("game_id", "turn_number", name="uq_game_states_game_turn"),
        schema="parser",
    )
    op.create_index(
        "ix_game_states_game_id",
        "game_states",
        ["game_id"],
        schema="parser",
    )


def downgrade() -> None:
    op.drop_index("ix_game_states_game_id", table_name="game_states", schema="parser")
    op.drop_table("game_states", schema="parser")
    op.drop_index("ix_games_match_id", table_name="games", schema="parser")
    op.drop_table("games", schema="parser")
    op.drop_index("ix_matches_sha256", table_name="matches", schema="parser")
    op.drop_index("ix_matches_user_id_parsed_at", table_name="matches", schema="parser")
    op.drop_table("matches", schema="parser")
