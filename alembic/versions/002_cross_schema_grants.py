"""cross-schema REFERENCES grants — allow ingest to FK auth tables.

Revision ID: 002
Revises: 001
Create Date: 2026-04-24

The ingest service creates FKs from ``ingest.user_uploads`` to
``auth.users`` and ``auth.agent_registrations``. PostgreSQL requires
the REFERENCES privilege separately from SELECT for a role to create
a foreign-key constraint against another schema's table.

Because the root migration head runs before any service head, the
auth tables don't exist yet when this runs — so we grant REFERENCES
via ALTER DEFAULT PRIVILEGES (fires for tables subsequently created
by the invoking role in the auth schema) rather than a per-table
GRANT. This also ensures future auth tables keep working without
revisiting this migration.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA auth "
        "GRANT REFERENCES ON TABLES TO deep_analysis_ingest;"
    )


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA auth "
        "REVOKE REFERENCES ON TABLES FROM deep_analysis_ingest;"
    )
