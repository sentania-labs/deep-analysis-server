"""auth.users: add mtgo_usernames JSONB column.

Revision ID: 006
Revises: 005
Create Date: 2026-05-12

Stores the user's confirmed MTGO username(s) as a JSON array of
strings. Used by the analytics service at query time to identify
which player in a match is the uploader (hero vs opponent).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql  # noqa: I001

from alembic import op

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "mtgo_usernames",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("users", "mtgo_usernames", schema="auth")
