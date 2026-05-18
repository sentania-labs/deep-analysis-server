"""analytics.scraper_config — per-scraper runtime configuration.

Revision ID: 018
Revises: 017
Create Date: 2026-05-17

Adds ``analytics.scraper_config`` so admin users can enable/disable
scrapers and adjust their run intervals at runtime without restarting
the service. The scheduler loops read this table instead of env-based
settings.

Seeded with two rows: ``mtgo`` (enabled, 24 h) and ``mtgtop8``
(enabled, 24 h).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "018"
down_revision: str | None = "017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scraper_config",
        sa.Column("scraper_name", sa.String(64), primary_key=True),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column(
            "interval_hours",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("24"),
        ),
        schema="analytics",
    )

    # Seed the two known scrapers.
    op.execute(
        "INSERT INTO analytics.scraper_config (scraper_name, enabled, interval_hours) "
        "VALUES ('mtgo', TRUE, 24), ('mtgtop8', TRUE, 24)"
    )

    # Re-issue schema-wide grants for the new table.
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics "
        "TO deep_analysis_analytics;"
    )
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics "
        "TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.drop_table("scraper_config", schema="analytics")
