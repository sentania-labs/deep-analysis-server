"""Add ON UPDATE CASCADE to ingest.user_uploads.user_id FK.

Revision ID: 002
Revises: 001
Create Date: 2026-05-10

Background
----------
Mirror of auth-schema migration 005: the drift-correction helper in
``auth_service.bootstrap`` can re-issue ``admin@local``'s id when it
lands at the wrong UID. ``ingest.user_uploads.user_id`` references
``auth.users.id`` with ``ON DELETE CASCADE`` but no ``ON UPDATE``
clause, so the parent UPDATE would be rejected when admin@local has
prior uploads. Add ``ON UPDATE CASCADE`` so the FK follows the move.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_FK_NAME = "fk_user_uploads_user_id"
_TABLE = "user_uploads"
_COLUMN = "user_id"


def upgrade() -> None:
    op.drop_constraint(_FK_NAME, _TABLE, schema="ingest", type_="foreignkey")
    op.create_foreign_key(
        _FK_NAME,
        source_table=_TABLE,
        referent_table="users",
        local_cols=[_COLUMN],
        remote_cols=["id"],
        source_schema="ingest",
        referent_schema="auth",
        ondelete="CASCADE",
        onupdate="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(_FK_NAME, _TABLE, schema="ingest", type_="foreignkey")
    op.create_foreign_key(
        _FK_NAME,
        source_table=_TABLE,
        referent_table="users",
        local_cols=[_COLUMN],
        remote_cols=["id"],
        source_schema="ingest",
        referent_schema="auth",
        ondelete="CASCADE",
    )
