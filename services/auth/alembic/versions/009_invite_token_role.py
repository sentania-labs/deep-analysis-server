"""Add role column to invite_tokens.

Revision ID: 009
Revises: 008
Create Date: 2026-05-13

Allows admins to specify which role (user or admin) the invite
consumer receives upon registration. Defaults to 'user' for
backward compatibility with existing invites.
"""

from sqlalchemy import Column, String, text

from alembic import op

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invite_tokens",
        Column("role", String(32), nullable=False, server_default=text("'user'")),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("invite_tokens", "role", schema="auth")
