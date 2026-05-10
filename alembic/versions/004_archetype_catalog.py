"""archetypes catalog table — analytics.archetypes.

Revision ID: 004
Revises: 003
Create Date: 2026-05-09

The archetype catalog is admin-managed reference data: a list of MTG
archetypes (Burn, Murktide, Tron, …) with format and a list of
"defining cards" used by the rule-based classifier in the analytics
service. ``defining_cards`` is JSONB-encoded as a list of strings so
the editing UX can stay simple (one card per line, joined client-side).

Owning the table here (root alembic) rather than in a per-service
alembic keeps the cross-schema FK from ``parser.matches.archetype_id``
in 005 declarable on a guaranteed-existing target, regardless of which
service heads have run.

This is a deliberate exception to "analytics owns no tables" — the
archetype catalog *is* analytics reference data, not operational state.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    op.create_table(
        "archetypes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("format", sa.Text(), nullable=False),
        sa.Column(
            "defining_cards",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "sample_decklists",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
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
        schema="analytics",
    )
    op.create_index(
        "ix_archetypes_format",
        "archetypes",
        ["format"],
        schema="analytics",
    )

    # Analytics owns this table — grant the analytics role full
    # privileges. The base 001 migration only grants SELECT on analytics
    # because at that point the schema had no tables; this catalog is
    # the first analytics-owned table and needs ALL.
    op.execute(
        "GRANT ALL PRIVILEGES ON TABLE analytics.archetypes "
        "TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE analytics.archetypes "
        "FROM deep_analysis_analytics;"
    )
    op.drop_index(
        "ix_archetypes_format", table_name="archetypes", schema="analytics"
    )
    op.drop_table("archetypes", schema="analytics")
