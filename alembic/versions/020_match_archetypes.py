"""parser.match_archetypes — per-player archetype classification per match.

Revision ID: 020
Revises: 019
Create Date: 2026-05-17

Stores the archetype classification for *both* players (hero and
opponent) in a match.  The hero-side result is also written back to
``parser.matches.archetype_id`` for backward compatibility; this table
captures the opponent's archetype and the confidence score which the
single FK on matches cannot represent.

- ``match_id`` FK to parser.matches(id) ON DELETE CASCADE
- ``archetype_id`` FK to analytics.archetypes(id) ON DELETE SET NULL
- ``confidence`` — overlap fraction from the classifier [0.0, 1.0]
- Unique on (match_id, player_name)
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "020"
down_revision: str | None = "019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "match_archetypes",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "match_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "parser.matches.id",
                ondelete="CASCADE",
                name="match_archetypes_match_id_fkey",
            ),
            nullable=False,
        ),
        sa.Column("player_name", sa.Text(), nullable=False),
        sa.Column(
            "archetype_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "analytics.archetypes.id",
                ondelete="SET NULL",
                name="match_archetypes_archetype_id_fkey",
            ),
            nullable=True,
        ),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.UniqueConstraint(
            "match_id",
            "player_name",
            name="uq_match_archetypes_match_player",
        ),
        schema="parser",
    )
    op.create_index(
        "ix_match_archetypes_match_id",
        "match_archetypes",
        ["match_id"],
        schema="parser",
    )
    op.create_index(
        "ix_match_archetypes_archetype_id",
        "match_archetypes",
        ["archetype_id"],
        schema="parser",
    )

    # Grant parser service access to the new table.
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA parser "
        "TO deep_analysis_parser;"
    )
    op.execute(
        "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA parser "
        "TO deep_analysis_parser;"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_match_archetypes_archetype_id",
        table_name="match_archetypes",
        schema="parser",
    )
    op.drop_index(
        "ix_match_archetypes_match_id",
        table_name="match_archetypes",
        schema="parser",
    )
    op.drop_table("match_archetypes", schema="parser")
