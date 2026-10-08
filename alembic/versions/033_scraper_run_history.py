"""Add bounded completed scraper run history.

Revision ID: 033
Revises: 032
Create Date: 2026-10-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "033"
down_revision: str | None = "032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scraper_run_history",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("scraper_name", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("events_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_new", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_empty", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("results_stored", sa.Integer(), nullable=False, server_default="0"),
        sa.CheckConstraint("duration_seconds >= 0", name="ck_scraper_history_duration"),
        sa.CheckConstraint("status IN ('success', 'failed')", name="ck_scraper_history_status"),
        schema="analytics",
    )
    op.create_index(
        "ix_scraper_run_history_name_started",
        "scraper_run_history",
        ["scraper_name", sa.text("started_at DESC")],
        schema="analytics",
    )
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_scraper_run_history_name_started",
        table_name="scraper_run_history",
        schema="analytics",
    )
    op.drop_table("scraper_run_history", schema="analytics")
