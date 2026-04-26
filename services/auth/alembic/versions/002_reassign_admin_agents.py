"""Reassign admin-owned agents to a target user (W3.6 sub-item 1).

Revision ID: 002
Revises: 001
Create Date: 2026-04-26

Background
----------
W3.6 makes admin a purely-administrative role: admins cannot register
or own agents. To roll forward without losing data, any agent currently
owned by an admin user gets *reassigned* (not deleted) to a designated
target user. The reassignment is reversible: an inverse mapping is
written into ``auth._agent_reassignment_log`` on upgrade and replayed
on downgrade.

Configuration
-------------
The reassignment target user is configurable via the
``DA_AGENT_REASSIGN_TARGET_EMAIL`` env var (default ``testuser@local``).
The target user must already exist; if no admin-owned agents are
found, the env var is ignored and the migration is a no-op aside from
creating the empty log table.

The check constraint on ``users.role`` is already in place from
``001_auth_tables.py`` — we leave it alone.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_DEFAULT_TARGET_EMAIL = "testuser@local"


def _target_email() -> str:
    return os.environ.get("DA_AGENT_REASSIGN_TARGET_EMAIL", _DEFAULT_TARGET_EMAIL)


def upgrade() -> None:
    # Inverse-mapping log — created unconditionally so downgrade has a
    # stable target to read+drop, even when there were no admin-owned
    # agents at upgrade time.
    op.create_table(
        "_agent_reassignment_log",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "agent_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("prior_user_id", sa.Integer(), nullable=False),
        sa.Column("new_user_id", sa.Integer(), nullable=False),
        sa.Column(
            "reassigned_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema="auth",
    )

    conn = op.get_bind()

    admin_agents = conn.execute(
        sa.text(
            "SELECT ar.id AS agent_id, ar.user_id AS prior_user_id "
            "FROM auth.agent_registrations ar "
            "JOIN auth.users u ON u.id = ar.user_id "
            "WHERE u.role = 'admin'"
        )
    ).fetchall()

    if not admin_agents:
        return

    target_email = _target_email()
    target = conn.execute(
        sa.text("SELECT id FROM auth.users WHERE lower(email) = lower(:email)"),
        {"email": target_email},
    ).fetchone()
    if target is None:
        raise RuntimeError(
            f"agent reassignment target user {target_email!r} not found in auth.users; "
            "set DA_AGENT_REASSIGN_TARGET_EMAIL to an existing user's email and re-run"
        )
    target_id = int(target.id)

    for row in admin_agents:
        conn.execute(
            sa.text(
                "INSERT INTO auth._agent_reassignment_log "
                "(agent_id, prior_user_id, new_user_id) "
                "VALUES (:aid, :prior, :new)"
            ),
            {"aid": row.agent_id, "prior": row.prior_user_id, "new": target_id},
        )
        conn.execute(
            sa.text("UPDATE auth.agent_registrations SET user_id = :new WHERE id = :aid"),
            {"new": target_id, "aid": row.agent_id},
        )


def downgrade() -> None:
    conn = op.get_bind()

    inspector = sa.inspect(conn)
    if not inspector.has_table("_agent_reassignment_log", schema="auth"):
        return

    log_rows = conn.execute(
        sa.text("SELECT agent_id, prior_user_id FROM auth._agent_reassignment_log ORDER BY id")
    ).fetchall()

    for row in log_rows:
        # Restore prior ownership only when the agent still exists.
        # An agent that's been deleted post-upgrade can't be restored,
        # but we don't fail the downgrade for it either.
        conn.execute(
            sa.text("UPDATE auth.agent_registrations SET user_id = :prior WHERE id = :aid"),
            {"prior": row.prior_user_id, "aid": row.agent_id},
        )

    op.drop_table("_agent_reassignment_log", schema="auth")
