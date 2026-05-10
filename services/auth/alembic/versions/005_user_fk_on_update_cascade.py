"""Add ON UPDATE CASCADE to FK constraints referencing auth.users.id.

Revision ID: 005
Revises: 004
Create Date: 2026-05-10

Background
----------
The drift-correction helper in ``auth_service.bootstrap`` issues
``UPDATE auth.users SET id = 1 WHERE id = <old_id>`` to move
``admin@local`` back to UID=1 when it landed at a different id (the
web settings page is gated on UID=1 via ``require_root_admin``). The
original FK constraints were declared with ``ON DELETE CASCADE`` (or
``ON DELETE SET NULL``) but no ``ON UPDATE`` clause — PostgreSQL
defaults the latter to ``NO ACTION``, so the parent UPDATE is rejected
whenever referencing rows exist (sessions, agent_registrations,
invite_tokens, server_settings).

This migration drops and re-adds the five FK constraints in the auth
schema with the same ``ON DELETE`` behavior plus ``ON UPDATE CASCADE``
so child rows follow the admin to its new id without manual cleanup.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_FK_CHANGES = [
    # (table, constraint_name, column, on_delete)
    ("sessions", "sessions_user_id_fkey", "user_id", "CASCADE"),
    (
        "agent_registrations",
        "agent_registrations_user_id_fkey",
        "user_id",
        "CASCADE",
    ),
    (
        "server_settings",
        "server_settings_updated_by_user_id_fkey",
        "updated_by_user_id",
        "SET NULL",
    ),
    (
        "invite_tokens",
        "invite_tokens_created_by_user_id_fkey",
        "created_by_user_id",
        "SET NULL",
    ),
    (
        "invite_tokens",
        "invite_tokens_used_by_user_id_fkey",
        "used_by_user_id",
        "SET NULL",
    ),
]


def upgrade() -> None:
    for table, name, column, on_delete in _FK_CHANGES:
        op.drop_constraint(name, table, schema="auth", type_="foreignkey")
        op.create_foreign_key(
            name,
            source_table=table,
            referent_table="users",
            local_cols=[column],
            remote_cols=["id"],
            source_schema="auth",
            referent_schema="auth",
            ondelete=on_delete,
            onupdate="CASCADE",
        )


def downgrade() -> None:
    for table, name, column, on_delete in _FK_CHANGES:
        op.drop_constraint(name, table, schema="auth", type_="foreignkey")
        op.create_foreign_key(
            name,
            source_table=table,
            referent_table="users",
            local_cols=[column],
            remote_cols=["id"],
            source_schema="auth",
            referent_schema="auth",
            ondelete=on_delete,
        )
