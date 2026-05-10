"""catalog.cards — Scryfall bulk-data card mirror.

Revision ID: 006
Revises: 005
Create Date: 2026-05-10

A new ``catalog`` schema for reference data — separate from
``analytics.*`` because cards are not analytics state, they're a
periodically-refreshed mirror of Scryfall's oracle bulk data. The
analytics service owns the table (it's the only service that reads or
writes it for now), but it lives outside the analytics schema so the
boundary stays clean if a future service ever consumes it too.

Schema and grants live together in this migration so the catalog
schema doesn't accumulate drift across multiple files. The analytics
role gets full privileges — it owns the upsert path; the parser role
gets SELECT for opportunistic card lookups (e.g., enriching match
games with card metadata at parse time).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS catalog;")

    op.create_table(
        "cards",
        sa.Column(
            "scryfall_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("oracle_text", sa.Text(), nullable=True),
        sa.Column("type_line", sa.Text(), nullable=True),
        sa.Column("mana_cost", sa.Text(), nullable=True),
        sa.Column(
            "colors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("set_code", sa.Text(), nullable=True),
        sa.Column("image_uri", sa.Text(), nullable=True),
        sa.Column("art_crop_uri", sa.Text(), nullable=True),
        sa.Column(
            "synced_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema="catalog",
    )
    op.create_index(
        "cards_name_idx",
        "cards",
        ["name"],
        schema="catalog",
    )

    # Analytics owns this table — full privileges on the schema and
    # the cards table. ALTER DEFAULT PRIVILEGES so any future catalog
    # tables created by the analytics role inherit the grant.
    op.execute("GRANT USAGE ON SCHEMA catalog TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA catalog "
        "TO deep_analysis_analytics;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA catalog "
        "GRANT ALL PRIVILEGES ON TABLES TO deep_analysis_analytics;"
    )

    # Parser reads cards opportunistically for match enrichment.
    op.execute("GRANT USAGE ON SCHEMA catalog TO deep_analysis_parser;")
    op.execute(
        "GRANT SELECT ON ALL TABLES IN SCHEMA catalog "
        "TO deep_analysis_parser;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA catalog "
        "GRANT SELECT ON TABLES TO deep_analysis_parser;"
    )


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA catalog "
        "REVOKE SELECT ON TABLES FROM deep_analysis_parser;"
    )
    op.execute(
        "REVOKE SELECT ON ALL TABLES IN SCHEMA catalog "
        "FROM deep_analysis_parser;"
    )
    op.execute("REVOKE USAGE ON SCHEMA catalog FROM deep_analysis_parser;")

    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA catalog "
        "REVOKE ALL PRIVILEGES ON TABLES FROM deep_analysis_analytics;"
    )
    op.execute(
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA catalog "
        "FROM deep_analysis_analytics;"
    )
    op.execute("REVOKE USAGE ON SCHEMA catalog FROM deep_analysis_analytics;")

    op.drop_index("cards_name_idx", table_name="cards", schema="catalog")
    op.drop_table("cards", schema="catalog")
    op.execute("DROP SCHEMA IF EXISTS catalog CASCADE;")
