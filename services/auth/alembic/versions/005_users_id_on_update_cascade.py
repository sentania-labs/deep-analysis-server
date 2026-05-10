"""Add ON UPDATE CASCADE to all FKs referencing auth.users.id.

Revision ID: 005
Revises: 004
Create Date: 2026-05-10

Background
----------
The UID 1 = admin@local invariant requires reclaim_uid1 to move
admin@local back to id=1 when it has drifted. The raw UPDATE
``auth.users SET id = 1`` fails at end-of-statement under the
default ON UPDATE NO ACTION semantics whenever child tables
(``sessions``, ``agent_registrations``, ``server_settings``,
``invite_tokens``) still reference the old id. Switching the five
inbound FKs to ON UPDATE CASCADE lets PostgreSQL propagate the new
parent id to children automatically, preserving sessions, agent
registrations, audit pointers, and invite history through the
reclaim.

ON DELETE behavior is unchanged: CASCADE for sessions and
agent_registrations, SET NULL for server_settings audit pointer and
the two invite_tokens audit pointers.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# (table, column, fk_name, ondelete) — fk_name follows PostgreSQL's
# default <table>_<column>_fkey since none of the prior migrations
# named these constraints.
_FKS = [
    ("sessions", "user_id", "sessions_user_id_fkey", "CASCADE"),
    (
        "agent_registrations",
        "user_id",
        "agent_registrations_user_id_fkey",
        "CASCADE",
    ),
    (
        "server_settings",
        "updated_by_user_id",
        "server_settings_updated_by_user_id_fkey",
        "SET NULL",
    ),
    (
        "invite_tokens",
        "created_by_user_id",
        "invite_tokens_created_by_user_id_fkey",
        "SET NULL",
    ),
    (
        "invite_tokens",
        "used_by_user_id",
        "invite_tokens_used_by_user_id_fkey",
        "SET NULL",
    ),
]


def upgrade() -> None:
    for table, column, fk_name, ondelete in _FKS:
        op.drop_constraint(fk_name, table, type_="foreignkey", schema="auth")
        op.create_foreign_key(
            fk_name,
            table,
            "users",
            [column],
            ["id"],
            source_schema="auth",
            referent_schema="auth",
            ondelete=ondelete,
            onupdate="CASCADE",
        )


def downgrade() -> None:
    for table, column, fk_name, ondelete in _FKS:
        op.drop_constraint(fk_name, table, type_="foreignkey", schema="auth")
        op.create_foreign_key(
            fk_name,
            table,
            "users",
            [column],
            ["id"],
            source_schema="auth",
            referent_schema="auth",
            ondelete=ondelete,
        )
