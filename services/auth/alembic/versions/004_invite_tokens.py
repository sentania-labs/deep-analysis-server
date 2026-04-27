"""User invite tokens table (W3.6 sub-item 4).

Revision ID: 004
Revises: 003
Create Date: 2026-04-26

Background
----------
W3.6 sub-item 4 introduces single-use invite tokens that admins mint
to onboard new users. In ``invite_only`` mode (the default seeded by
migration 003) signup is gated by a token; in ``open`` mode tokens are
optional but still consumed when present so admins can hand out
trackable links for friction-free onboarding.

Shape
-----
``invite_tokens(id UUID PK, token_hash UNIQUE, created_by_user_id FK
users SET NULL, created_at, expires_at, used_at NULL,
used_by_user_id FK users SET NULL NULL)``. Plaintext is **never**
stored — the issuing endpoint returns the plaintext once and persists
only the SHA-256 hex digest.

Pattern mirrors agent registration codes (single-use, hashed-at-rest,
plaintext-once) but lives in Postgres rather than Redis because
invites have a 7-day default TTL and need an audit trail (who minted,
who consumed) — the registration-code Redis store is the wrong shape
for both.

FK ``ON DELETE SET NULL`` on both ``created_by_user_id`` and
``used_by_user_id`` so deleting an admin doesn't cascade-wipe the
invite history. Index on ``(used_at, expires_at)`` so the pending-list
query (``used_at IS NULL AND expires_at > now()``) doesn't seq-scan
once invite volume grows.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "invite_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by_user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["auth.users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["used_by_user_id"], ["auth.users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("token_hash", name="uq_invite_tokens_token_hash"),
        schema="auth",
    )
    op.create_index(
        "ix_invite_tokens_pending",
        "invite_tokens",
        ["used_at", "expires_at"],
        schema="auth",
    )


def downgrade() -> None:
    op.drop_index("ix_invite_tokens_pending", table_name="invite_tokens", schema="auth")
    op.drop_table("invite_tokens", schema="auth")
