"""catalog.cards: add legalities JSONB; parser.matches: add format_source.

Revision ID: 009
Revises: 008
Create Date: 2026-05-12

Legalities support format inference from card pools. The Scryfall
bulk sync already downloads legality data per card; this migration
adds the column to persist it.

format_source tracks whether the match format was inferred from the
card pool, inherited from a scraped MTGO event, or set by the user.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cards",
        sa.Column(
            "legalities",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        schema="catalog",
    )
    op.add_column(
        "matches",
        sa.Column("format_source", sa.String(length=32), nullable=True),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_column("matches", "format_source", schema="parser")
    op.drop_column("cards", "legalities", schema="catalog")
