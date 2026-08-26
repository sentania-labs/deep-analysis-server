"""analytics.scraper_runs: per-scraper run lock (issue #127).

Revision ID: 031
Revises: 030
Create Date: 2026-08-26

One row per scraper that is currently running. Presence of a row whose
``heartbeat_at`` is recent means "a run is in progress"; absence (or a
stale heartbeat) means "idle".

The row is the lock *and* the ``running_since`` display value, so there
is exactly one source of truth for both. A running scrape refreshes
``heartbeat_at`` on a timer; if the process dies without releasing, the
heartbeat stops advancing and the row becomes stale, at which point the
next acquirer takes it over. That is the stale-lock story: no run is
blocked forever by a killed container.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "031"
down_revision: str | None = "030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scraper_runs",
        sa.Column("scraper_name", sa.String(64), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("trigger", sa.String(16), nullable=False, server_default=sa.text("'manual'")),
        sa.Column("owner", sa.String(128), nullable=True),
        schema="analytics",
    )

    # Re-issue schema-wide grants for the new table.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.drop_table("scraper_runs", schema="analytics")
