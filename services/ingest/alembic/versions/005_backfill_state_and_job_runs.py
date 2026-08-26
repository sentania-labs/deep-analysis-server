"""ingest.job_runs + ingest.backfill_state: automatic raw-archive backfill (issue #161).

Revision ID: 005
Revises: 004
Create Date: 2026-08-26

Two tables, both tiny, both there so the migration from the legacy
filesystem archive can run itself without an operator driving it.

``job_runs`` is the multi-replica lock, the same heartbeat-row shape
analytics uses for its scrapers (``analytics.scraper_runs``, root
revision 031). Generalised into ``common.job_lock``; this is ingest's
copy of the table because each service owns its own schema and the
ingest role has no rights in the analytics one.

``backfill_state`` is the durable answer to "is this done?". Without
it, every boot would have to re-derive completion by scanning thousands
of rows against the object store forever. With it, a completed
migration costs one primary-key read at startup and stops there. It
also carries the progress counters, so how far along a running
migration is can be read from an admin endpoint or scraped as metrics
rather than dug out of container logs.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Every value ``backfill_state.status`` may hold.
#
#   pending     nothing has run yet
#   running     a replica holds the lock and is migrating right now
#   complete    every row verified present in the object store; the
#               terminal state, and the one that makes later boots free
#   incomplete  the run made progress or hit a retryable error; the
#               next start tries again
#   stalled     the run could do nothing more (source files genuinely
#               absent). Auto-runs stop retrying; a manual trigger still
#               works. This is what keeps a permanently-unfixable
#               remainder from re-scanning on every boot forever.
_STATUS_CHECK = "status IN ('pending', 'running', 'complete', 'incomplete', 'stalled')"


def upgrade() -> None:
    op.create_table(
        "job_runs",
        sa.Column("job_name", sa.String(64), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("trigger", sa.String(16), nullable=False, server_default=sa.text("'manual'")),
        sa.Column("owner", sa.String(128), nullable=True),
        schema="ingest",
    )

    op.create_table(
        "backfill_state",
        sa.Column("job_name", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("expected", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("processed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("uploaded", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("already_present", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("missing_source", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("hash_mismatch", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("failed", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("verified", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("verify_errors", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("bytes_uploaded", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("source_root", sa.String(512), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.CheckConstraint(
            _STATUS_CHECK,
            name="ck_backfill_state_status",
        ),
        schema="ingest",
    )

    # Re-issue schema-wide grants for the new tables.
    op.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA ingest TO deep_analysis_ingest;")
    op.execute("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA ingest TO deep_analysis_ingest;")


def downgrade() -> None:
    op.drop_table("backfill_state", schema="ingest")
    op.drop_table("job_runs", schema="ingest")
