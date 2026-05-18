"""parser.deck_compositions — deck composition ingest from MTGO grouping XML.

Revision ID: 022
Revises: 021
Create Date: 2026-05-17

Two tables: ``deck_compositions`` stores the parsed grouping file header
(deck name, net_deck_id, format, timestamp) and ``deck_composition_items``
stores the individual card entries with CatId → card_name resolution.

Also adds ``deck_composition_id`` nullable FK on ``parser.matches`` to link
a match to its most-likely deck composition.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- deck_compositions ---------------------------------------------------
    op.create_table(
        "deck_compositions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("deck_uuid", sa.Text(), nullable=True),
        sa.Column("net_deck_id", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("grouping_type", sa.Text(), nullable=False),
        sa.Column("format_code", sa.Text(), nullable=True),
        sa.Column("deck_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "parsed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("sha256", "user_id", name="uq_deck_compositions_sha256_user"),
        schema="parser",
    )
    op.create_index(
        "ix_deck_compositions_user_id",
        "deck_compositions",
        ["user_id"],
        schema="parser",
    )
    op.create_index(
        "ix_deck_compositions_format_code",
        "deck_compositions",
        ["format_code"],
        schema="parser",
    )

    # --- deck_composition_items ----------------------------------------------
    op.create_table(
        "deck_composition_items",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "deck_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parser.deck_compositions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mtgo_id", sa.Integer(), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("is_sideboard", sa.Boolean(), nullable=False),
        sa.Column("card_name", sa.Text(), nullable=True),
        schema="parser",
    )
    op.create_index(
        "ix_deck_composition_items_deck_id",
        "deck_composition_items",
        ["deck_id"],
        schema="parser",
    )
    op.create_index(
        "ix_deck_composition_items_mtgo_id",
        "deck_composition_items",
        ["mtgo_id"],
        schema="parser",
    )

    # --- matches.deck_composition_id -----------------------------------------
    op.add_column(
        "matches",
        sa.Column(
            "deck_composition_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("parser.deck_compositions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        schema="parser",
    )

    # Grant parser service role access to the new tables.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA parser TO deep_analysis_parser;")
    op.execute("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA parser TO deep_analysis_parser;")
    # Parser needs SELECT on catalog.cards for CatId → card_name resolution.
    # (May already be granted by 021; idempotent.)
    op.execute("GRANT SELECT ON catalog.cards TO deep_analysis_parser;")
    # Parser needs SELECT on ingest.user_uploads to look up original_filename.
    # The table is created by the ingest service's own alembic chain, which
    # runs after the root chain in CI.  Use IF EXISTS so this is a no-op when
    # the table hasn't been created yet; compose-smoke (and production) will
    # re-apply via the ingest-migrate container's grants.
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'ingest' AND table_name = 'user_uploads') THEN "
        "EXECUTE 'GRANT SELECT ON ingest.user_uploads TO deep_analysis_parser'; "
        "END IF; END $$;"
    )


def downgrade() -> None:
    op.drop_column("matches", "deck_composition_id", schema="parser")
    op.drop_index(
        "ix_deck_composition_items_mtgo_id",
        table_name="deck_composition_items",
        schema="parser",
    )
    op.drop_index(
        "ix_deck_composition_items_deck_id",
        table_name="deck_composition_items",
        schema="parser",
    )
    op.drop_table("deck_composition_items", schema="parser")
    op.drop_index(
        "ix_deck_compositions_format_code",
        table_name="deck_compositions",
        schema="parser",
    )
    op.drop_index(
        "ix_deck_compositions_user_id",
        table_name="deck_compositions",
        schema="parser",
    )
    op.drop_table("deck_compositions", schema="parser")
