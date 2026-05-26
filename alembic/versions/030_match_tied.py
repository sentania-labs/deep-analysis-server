"""parser.matches.match_tied: explicit flag for intentional draws.

Revision ID: 030
Revises: 029
Create Date: 2026-05-26

Adds a non-nullable ``match_tied`` BOOLEAN column (default FALSE) to
``parser.matches``.  The parser sets this to TRUE when the MTGO log
contains a "Match Tied" line.  The analytics layer uses it to
distinguish intentional draws (0-0 game wins with match_tied=True)
from partial/unresolved parses (0-0 game wins with match_tied=False).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "030"
down_revision: str | None = "029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "matches",
        sa.Column("match_tied", sa.Boolean(), nullable=False, server_default="false"),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_column("matches", "match_tied", schema="parser")
