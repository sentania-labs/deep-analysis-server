"""parser.matches.archetype_id — FK to analytics.archetypes.

Revision ID: 005
Revises: 004
Create Date: 2026-05-09

Adds a nullable ``archetype_id`` column to ``parser.matches`` with a
foreign key into ``analytics.archetypes.id``. The parser fills this in
opportunistically by calling the analytics classifier endpoint after
persisting a match — null means "not classified yet" or "classifier
returned no match".

Cross-schema FK: PostgreSQL needs both SELECT (so the parser role can
look up the target row) and REFERENCES (to declare the constraint
itself) on the analytics schema. We grant SELECT directly and use
ALTER DEFAULT PRIVILEGES for REFERENCES so any future tables added to
the analytics schema by the analytics role will also be referenceable.
``ON DELETE SET NULL`` on the FK so an admin deleting an archetype
doesn't cascade-wipe match rows; the match just loses its
classification until re-run.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Cross-schema grants — parser needs SELECT to read archetype rows
    # at FK-validate time, and REFERENCES to declare the constraint.
    op.execute("GRANT USAGE ON SCHEMA analytics TO deep_analysis_parser;")
    op.execute(
        "GRANT SELECT, REFERENCES ON ALL TABLES IN SCHEMA analytics "
        "TO deep_analysis_parser;"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics "
        "GRANT SELECT, REFERENCES ON TABLES TO deep_analysis_parser;"
    )

    op.add_column(
        "matches",
        sa.Column(
            "archetype_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        schema="parser",
    )
    op.create_foreign_key(
        "fk_matches_archetype_id",
        source_table="matches",
        referent_table="archetypes",
        local_cols=["archetype_id"],
        remote_cols=["id"],
        ondelete="SET NULL",
        source_schema="parser",
        referent_schema="analytics",
    )
    op.create_index(
        "ix_matches_archetype_id",
        "matches",
        ["archetype_id"],
        schema="parser",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_matches_archetype_id", table_name="matches", schema="parser"
    )
    op.drop_constraint(
        "fk_matches_archetype_id",
        "matches",
        type_="foreignkey",
        schema="parser",
    )
    op.drop_column("matches", "archetype_id", schema="parser")

    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics "
        "REVOKE SELECT, REFERENCES ON TABLES FROM deep_analysis_parser;"
    )
    op.execute(
        "REVOKE SELECT, REFERENCES ON ALL TABLES IN SCHEMA analytics "
        "FROM deep_analysis_parser;"
    )
    op.execute("REVOKE USAGE ON SCHEMA analytics FROM deep_analysis_parser;")
