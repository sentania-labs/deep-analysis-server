"""B&R events table — analytics.bnr_events.

Revision ID: 028
Revises: 027
Create Date: 2026-05-25

Banned & Restricted epoch tracking for dashboard date filters.
Admin-managed reference data: each row represents a B&R announcement
with format, effective date, and a JSONB list of card actions
(e.g. ``[{"card": "Fury", "action": "banned"}]``).

Like the archetype catalog (004), this is analytics reference data
owned by the analytics service, not operational state.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "028"
down_revision: str | None = "027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "bnr_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("format", sa.Text(), nullable=False),
        sa.Column("effective_date", sa.Date(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "card_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "format", "effective_date", name="bnr_events_format_effective_date_key"
        ),
        schema="analytics",
    )
    op.create_index(
        "ix_bnr_events_format_effective_date",
        "bnr_events",
        ["format", sa.text("effective_date DESC")],
        schema="analytics",
    )

    op.execute("GRANT ALL PRIVILEGES ON TABLE analytics.bnr_events TO deep_analysis_analytics;")


def downgrade() -> None:
    op.execute("REVOKE ALL PRIVILEGES ON TABLE analytics.bnr_events FROM deep_analysis_analytics;")
    op.drop_index(
        "ix_bnr_events_format_effective_date", table_name="bnr_events", schema="analytics"
    )
    op.drop_table("bnr_events", schema="analytics")
