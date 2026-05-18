"""parser.matches.hero_player_name: resolved hero at parse time.

Revision ID: 016
Revises: 015
Create Date: 2026-05-17

Adds a nullable TEXT column ``hero_player_name`` to ``parser.matches``
that stores the MTGO username of the uploader (hero) as resolved
against ``auth.users.mtgo_usernames`` at parse time. This eliminates
the need for analytics to re-resolve the hero on every query.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "matches",
        sa.Column("hero_player_name", sa.Text, nullable=True),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_column("matches", "hero_player_name", schema="parser")
