"""catalog.cards: add oracle_id and mtgo_id columns.

Revision ID: 014
Revises: 013
Create Date: 2026-05-17

oracle_id (UUID, nullable) — Scryfall's oracle identifier, shared across
all printings of the same card. Double-faced cards share the same oracle_id
for both faces. Non-unique index because DFCs produce multiple rows with
the same oracle_id.

mtgo_id (INTEGER, nullable) — MTGO's internal CatId. Not every Scryfall
card has one (paper-only printings, tokens, etc.), so nullable. Unique
where present — each MTGO CatId maps to exactly one card printing.

These columns are prerequisites for the card analytics engine: oracle_id
enables reprint aggregation, mtgo_id enables resolving MTGO deck
composition files to card names.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "014"
down_revision: str | None = "013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "cards",
        sa.Column("oracle_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="catalog",
    )
    op.add_column(
        "cards",
        sa.Column("mtgo_id", sa.Integer(), nullable=True),
        schema="catalog",
    )

    # Non-unique: DFCs share oracle_id across faces.
    op.create_index(
        "cards_oracle_id_idx",
        "cards",
        ["oracle_id"],
        schema="catalog",
    )

    # Unique where present — nullable columns are excluded from unique
    # constraints by Postgres (NULLs are always distinct), so this
    # naturally allows multiple rows with mtgo_id IS NULL.
    op.create_index(
        "cards_mtgo_id_idx",
        "cards",
        ["mtgo_id"],
        unique=True,
        schema="catalog",
    )


def downgrade() -> None:
    op.drop_index("cards_mtgo_id_idx", table_name="cards", schema="catalog")
    op.drop_index("cards_oracle_id_idx", table_name="cards", schema="catalog")
    op.drop_column("cards", "mtgo_id", schema="catalog")
    op.drop_column("cards", "oracle_id", schema="catalog")
