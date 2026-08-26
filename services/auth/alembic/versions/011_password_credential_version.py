"""auth: credential version columns for password-reset session invalidation.

Revision ID: 011
Revises: 010
Create Date: 2026-08-26

Adds two nullable TIMESTAMPTZ columns:

- ``auth.users.password_changed_at``: stamped every time a password
  hash is written (admin reset, self-service change, bootstrap force
  reset, account creation).
- ``auth.sessions.password_epoch``: the ``password_changed_at`` value
  the issuing login/refresh read off the user row.

Session resolution rejects a session whose ``password_epoch`` no longer
equals the user's ``password_changed_at``.

DEPLOY SAFETY: both columns are backfilled as NULL, on purpose. Existing
users get ``password_changed_at = NULL`` and existing sessions get
``password_epoch = NULL``; NULL equals NULL under the resolution check,
so nobody is signed out by this migration. Backfilling either column to
``now()`` would sign out every logged-in user on deploy.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        schema="auth",
    )
    op.add_column(
        "sessions",
        sa.Column("password_epoch", sa.DateTime(timezone=True), nullable=True),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("sessions", "password_epoch", schema="auth")
    op.drop_column("users", "password_changed_at", schema="auth")
