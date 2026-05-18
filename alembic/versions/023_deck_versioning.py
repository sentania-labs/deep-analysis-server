"""parser.deck_version_links — deck versioning and diff tracking.

Revision ID: 023
Revises: 022
Create Date: 2026-05-18

Adds ``file_mtime`` and ``version_number`` columns to
``parser.deck_compositions`` and creates ``parser.deck_version_links``
to track version chains and card-level diffs across uploads of the
same logical deck.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "023"
down_revision: str | None = "022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- deck_compositions: add file_mtime + version_number ----------------
    op.add_column(
        "deck_compositions",
        sa.Column("file_mtime", sa.Float(), nullable=True),
        schema="parser",
    )
    op.add_column(
        "deck_compositions",
        sa.Column(
            "version_number",
            sa.Integer(),
            nullable=True,
            server_default="1",
        ),
        schema="parser",
    )

    # --- deck_version_links ------------------------------------------------
    op.create_table(
        "deck_version_links",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("deck_identity", sa.Text(), nullable=False),
        sa.Column(
            "deck_composition_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parser.deck_compositions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column(
            "previous_composition_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parser.deck_compositions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("cards_added", postgresql.JSONB(), nullable=True),
        sa.Column("cards_removed", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "user_id",
            "deck_identity",
            "version_number",
            name="uq_deck_version_links_user_identity_version",
        ),
        schema="parser",
    )
    op.create_index(
        "ix_deck_version_links_user_identity",
        "deck_version_links",
        ["user_id", "deck_identity"],
        schema="parser",
    )
    op.create_index(
        "ix_deck_version_links_composition_id",
        "deck_version_links",
        ["deck_composition_id"],
        schema="parser",
    )

    # Grant parser service role access to the new table and columns.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA parser TO deep_analysis_parser;")
    op.execute("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA parser TO deep_analysis_parser;")


def downgrade() -> None:
    op.drop_index(
        "ix_deck_version_links_composition_id",
        table_name="deck_version_links",
        schema="parser",
    )
    op.drop_index(
        "ix_deck_version_links_user_identity",
        table_name="deck_version_links",
        schema="parser",
    )
    op.drop_table("deck_version_links", schema="parser")
    op.drop_column("deck_compositions", "version_number", schema="parser")
    op.drop_column("deck_compositions", "file_mtime", schema="parser")
