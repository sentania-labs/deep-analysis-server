"""analytics.canonical_archetypes / archetype_label_mappings — ML classifier taxonomy.

Revision ID: 019
Revises: 018
Create Date: 2026-05-17

Two new tables in the ``analytics`` schema for the ML archetype
classifier:

- ``canonical_archetypes`` — admin-managed taxonomy of archetype names
  per format, with optional variant tags for finer-grained labelling.
- ``archetype_label_mappings`` — maps raw deck_name strings from
  mtgtop8 scraper results to canonical archetype IDs. Serves as
  training-label curation for the ML classifier.

Grants follow the same schema-wide pattern as earlier migrations.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "019"
down_revision: str | None = "018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "canonical_archetypes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("uuid_generate_v4()"),
        ),
        sa.Column("canonical_name", sa.Text(), nullable=False),
        sa.Column("format", sa.Text(), nullable=False),
        sa.Column(
            "variant_tags",
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
        sa.UniqueConstraint(
            "canonical_name",
            "format",
            name="canonical_archetypes_name_format_key",
        ),
        schema="analytics",
    )

    op.create_table(
        "archetype_label_mappings",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("scraped_label", sa.Text(), nullable=False),
        sa.Column(
            "canonical_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "analytics.canonical_archetypes.id",
                ondelete="CASCADE",
                name="archetype_label_mappings_canonical_id_fkey",
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "scraped_label",
            "canonical_id",
            name="archetype_label_mappings_label_canonical_key",
        ),
        schema="analytics",
    )
    op.create_index(
        "archetype_label_mappings_scraped_label_idx",
        "archetype_label_mappings",
        ["scraped_label"],
        schema="analytics",
    )

    # Re-issue schema-wide grants for the new tables.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA analytics TO deep_analysis_analytics;")
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA analytics TO deep_analysis_analytics;"
    )


def downgrade() -> None:
    op.drop_index(
        "archetype_label_mappings_scraped_label_idx",
        table_name="archetype_label_mappings",
        schema="analytics",
    )
    op.drop_table("archetype_label_mappings", schema="analytics")
    op.drop_table("canonical_archetypes", schema="analytics")
