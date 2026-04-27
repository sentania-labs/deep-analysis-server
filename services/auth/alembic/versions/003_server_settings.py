"""Server settings table + default registration_mode (W3.6 sub-item 3).

Revision ID: 003
Revises: 002
Create Date: 2026-04-26

Background
----------
W3.6 sub-item 3 introduces a UID=1-only toggle that selects whether
new-user registration is ``open`` (anyone may sign up) or
``invite_only`` (signup requires an admin-issued invite token, sub-item
4). The toggle's value lives in the new ``auth.server_settings`` table —
a generic key/value store sized for the handful of cluster-global
settings the server will need.

Shape
-----
``server_settings(key VARCHAR(64) PK, value JSONB, updated_at,
updated_by_user_id INT NULL ON DELETE SET NULL)``. JSONB lets future
settings carry structured payloads without another migration per key.
``updated_by_user_id`` is the audit pointer; deleting that admin row
nulls the column rather than cascading the setting away.

Default
-------
``registration_mode = "invite_only"`` is inserted at upgrade time so
fresh installs are locked-down by default. Sub-item 3 ships the toggle
that flips this; sub-item 4 wires the public /register route to read
it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "server_settings",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["auth.users.id"], ondelete="SET NULL"),
        schema="auth",
    )

    # Lock down by default. Sub-item 3 ships the toggle; sub-item 4
    # wires the public /register route to consult this row.
    op.execute(
        sa.text(
            "INSERT INTO auth.server_settings (key, value) "
            "VALUES ('registration_mode', '\"invite_only\"'::jsonb)"
        )
    )


def downgrade() -> None:
    op.drop_table("server_settings", schema="auth")
