"""analytics.mtgtop8_events / mtgtop8_results — mtgtop8.com results scraper.

Revision ID: 013
Revises: 012
Create Date: 2026-05-14

Two new tables in the ``analytics`` schema for the mtgtop8.com event
results scraper:

- ``mtgtop8_events`` — one row per published event (event_url is the
  natural dedup key). Includes an optional ``player_count`` column.
- ``mtgtop8_results`` — per-player rows attached to an event, with
  decklists as JSONB (main/sideboard) and an optional ``deck_name``
  for the archetype label from mtgtop8.

The existing ``analytics.scraper_health`` table (from migration 007) is
generic — the new scraper slots in with ``scraper_name='mtgtop8'``, no
schema change needed.

Grants follow the same schema-wide pattern as 007.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mtgtop8_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_name", sa.Text(), nullable=False),
        sa.Column("format", sa.Text(), nullable=True),
        sa.Column("event_date", sa.Date(), nullable=True),
        sa.Column("event_url", sa.Text(), nullable=False),
        sa.Column("player_count", sa.Integer(), nullable=True),
        sa.Column(
            "scraped_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("event_url", name="mtgtop8_events_event_url_key"),
        schema="analytics",
    )

    op.create_table(
        "mtgtop8_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "event_id",
            sa.Integer(),
            sa.ForeignKey(
                "analytics.mtgtop8_events.id",
                ondelete="CASCADE",
                name="mtgtop8_results_event_id_fkey",
            ),
            nullable=False,
        ),
        sa.Column("player_name", sa.Text(), nullable=False),
        sa.Column("placement", sa.Integer(), nullable=True),
        sa.Column("deck_name", sa.Text(), nullable=True),
        sa.Column(
            "decklist_main",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "decklist_sideboard",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        schema="analytics",
    )
    op.create_index(
        "mtgtop8_results_event_id_idx",
        "mtgtop8_results",
        ["event_id"],
        schema="analytics",
    )

    # Re-issue schema-wide grants for the new tables.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.drop_index(
        "mtgtop8_results_event_id_idx",
        table_name="mtgtop8_results",
        schema="analytics",
    )
    op.drop_table("mtgtop8_results", schema="analytics")
    op.drop_table("mtgtop8_events", schema="analytics")
