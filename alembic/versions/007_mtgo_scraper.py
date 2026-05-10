"""analytics.mtgo_events / mtgo_results / scraper_health — MTGO results scraper.

Revision ID: 007
Revises: 006
Create Date: 2026-05-10

Three new tables in the ``analytics`` schema for the MTGO public-event
results scraper:

- ``mtgo_events`` — one row per published event (event_url is the
  natural dedup key, since mtgo.com mints a stable URL per event).
- ``mtgo_results`` — per-player rows attached to an event, with the
  decklists captured as JSONB (main/sideboard) so we can ingest
  whatever schema the scraper produces without a schema-change cycle
  every time mtgo.com tweaks its layout.
- ``scraper_health`` — generic per-scraper health row. Tracks
  consecutive_failures and ``is_broken`` so we can alert when mtgo.com
  inevitably changes their HTML and our extraction breaks. Generic by
  design — when we add a second scraper (MTGGoldfish, etc.) it slots
  in by name.

Grants follow the pattern in 006: a schema-wide ALL + ALTER DEFAULT
PRIVILEGES re-issue. They're idempotent against the prior 004
table-level grant on ``analytics.archetypes`` and arm new analytics
tables to inherit ALL automatically.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mtgo_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_name", sa.Text(), nullable=False),
        sa.Column("format", sa.Text(), nullable=True),
        sa.Column("event_date", sa.Date(), nullable=True),
        sa.Column("event_url", sa.Text(), nullable=False),
        sa.Column(
            "scraped_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("event_url", name="mtgo_events_event_url_key"),
        schema="analytics",
    )

    op.create_table(
        "mtgo_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "event_id",
            sa.Integer(),
            sa.ForeignKey(
                "analytics.mtgo_events.id",
                ondelete="CASCADE",
                name="mtgo_results_event_id_fkey",
            ),
            nullable=False,
        ),
        sa.Column("player_name", sa.Text(), nullable=False),
        sa.Column("placement", sa.Integer(), nullable=True),
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
        "mtgo_results_event_id_idx",
        "mtgo_results",
        ["event_id"],
        schema="analytics",
    )

    op.create_table(
        "scraper_health",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scraper_name", sa.Text(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "is_broken",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_raw_snippet", sa.Text(), nullable=True),
        sa.UniqueConstraint("scraper_name", name="scraper_health_scraper_name_key"),
        schema="analytics",
    )

    # Analytics owns these tables — full privileges. Schema-wide grant
    # + default privileges follow the 006 pattern; idempotent over the
    # prior 004 table-level grant on analytics.archetypes.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO deep_analysis_analytics;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics "
        "GRANT ALL PRIVILEGES ON TABLES TO deep_analysis_analytics;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics "
        "GRANT ALL PRIVILEGES ON SEQUENCES TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics "
        "REVOKE ALL PRIVILEGES ON SEQUENCES FROM deep_analysis_analytics;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics "
        "REVOKE ALL PRIVILEGES ON TABLES FROM deep_analysis_analytics;"
    )

    op.drop_table("scraper_health", schema="analytics")
    op.drop_index(
        "mtgo_results_event_id_idx",
        table_name="mtgo_results",
        schema="analytics",
    )
    op.drop_table("mtgo_results", schema="analytics")
    op.drop_table("mtgo_events", schema="analytics")
