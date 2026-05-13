"""Add max_uses and use_count to invite_tokens.

Revision ID: 008
Revises: 007
Create Date: 2026-05-13

Supports multi-use invite tokens. max_uses NULL means unlimited;
use_count tracks how many registrations have consumed the token.
"""

from sqlalchemy import Column, Integer, text

from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invite_tokens",
        Column("max_uses", Integer(), nullable=True),
        schema="auth",
    )
    op.add_column(
        "invite_tokens",
        Column("use_count", Integer(), nullable=False, server_default=text("0")),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("invite_tokens", "use_count", schema="auth")
    op.drop_column("invite_tokens", "max_uses", schema="auth")
