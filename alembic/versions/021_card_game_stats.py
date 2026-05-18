"""analytics.card_game_stats — materialized per-game per-card stats.

Revision ID: 021
Revises: 020
Create Date: 2026-05-17

Pre-aggregated card performance data derived from ``parser.game_events``
at parse time.  Replaces the expensive LATERAL JSONB queries in the
card-stats endpoints with simple GROUP BY SELECTs.

One row per (game, card_name, is_local) — capturing seen/cast/played
counts, whether the game was won, game_number for G1/G2/G3 splits,
and oracle_id for cross-printing aggregation.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "021"
down_revision: str | None = "020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "card_game_stats",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "match_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "game_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "oracle_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("card_name", sa.Text(), nullable=False),
        sa.Column("is_local", sa.Boolean(), nullable=False),
        sa.Column("seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cast", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("played", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_postboard", sa.Boolean(), nullable=False),
        sa.Column("won", sa.Boolean(), nullable=True),
        sa.Column("quantity", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("game_number", sa.Integer(), nullable=False),
        sa.UniqueConstraint(
            "game_id",
            "card_name",
            "is_local",
            name="uq_card_game_stats_game_card_local",
        ),
        schema="analytics",
    )
    op.create_index(
        "ix_card_game_stats_match_id",
        "card_game_stats",
        ["match_id"],
        schema="analytics",
    )
    op.create_index(
        "ix_card_game_stats_game_id",
        "card_game_stats",
        ["game_id"],
        schema="analytics",
    )
    op.create_index(
        "ix_card_game_stats_oracle_id",
        "card_game_stats",
        ["oracle_id"],
        schema="analytics",
    )
    op.create_index(
        "ix_card_game_stats_is_local_oracle_id",
        "card_game_stats",
        ["is_local", "oracle_id"],
        schema="analytics",
    )

    # Grant analytics service access to the new table.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO deep_analysis_analytics;"
    )
    # Parser writes to this table too — cross-schema grant.
    op.execute("GRANT INSERT, UPDATE, DELETE ON analytics.card_game_stats TO deep_analysis_parser;")
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE analytics.card_game_stats_id_seq TO deep_analysis_parser;"
    )
    # Parser also needs SELECT on catalog.cards for oracle_id lookups.
    op.execute("GRANT SELECT ON catalog.cards TO deep_analysis_parser;")


def downgrade() -> None:
    op.drop_index(
        "ix_card_game_stats_is_local_oracle_id",
        table_name="card_game_stats",
        schema="analytics",
    )
    op.drop_index(
        "ix_card_game_stats_oracle_id",
        table_name="card_game_stats",
        schema="analytics",
    )
    op.drop_index(
        "ix_card_game_stats_game_id",
        table_name="card_game_stats",
        schema="analytics",
    )
    op.drop_index(
        "ix_card_game_stats_match_id",
        table_name="card_game_stats",
        schema="analytics",
    )
    op.drop_table("card_game_stats", schema="analytics")
