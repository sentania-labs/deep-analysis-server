"""parser.user_reparse_cooldown: per-user self-service reparse cooldown.

Revision ID: 026
Revises: 025
Create Date: 2026-05-24

Stores the timestamp of each user's most recent self-service reparse so
``POST /parser/me/reparse`` can enforce a 1-per-hour cooldown atomically
via ``INSERT ... ON CONFLICT (user_id) DO UPDATE ... WHERE`` and a
``RETURNING`` row to detect whether the gate opened.

Cooldown state was previously written to ``auth.server_settings``, which
the parser DB role has no grants on under least-privilege deployments —
the feature would have failed with ``permission denied`` in production.
This table is parser-owned so the parser role can write it directly.

No FK to ``auth.users``: cross-schema FKs require REFERENCES grants
across migration heads and load-order coordination; parser already
references ``user_id`` as a plain integer in ``parser.matches`` and
``parser.deck_compositions``. We match that convention. Orphan rows for
deleted users are harmless (PK on user_id; an admin-only janitor can
clean them if it ever matters).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_reparse_cooldown",
        sa.Column("user_id", sa.Integer(), primary_key=True),
        sa.Column(
            "last_reparse_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="parser",
    )


def downgrade() -> None:
    op.drop_table("user_reparse_cooldown", schema="parser")
