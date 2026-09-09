"""Durable admin review verdicts for replaceable match rows.

Revision ID: 032
Revises: 031
Create Date: 2026-09-09

The parser deduplicates a logical match by ``(user_id, raw_match_id)``
when MTGO supplied a match ID, with ``(user_id, sha256)`` as the legacy
fallback. This table stores the same identity outside ``parser.matches``
so force-reparse can replace match rows without losing admin decisions.
The source SHA remains as provenance even for canonical identities.

Existing rejected and pending-review matches are copied during the normal
root migration that runs before services start. This protects current
admin decisions on the first force-reparse after deployment.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "032"
down_revision: str | None = "031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "match_review_verdicts",
        sa.Column("user_id", sa.Integer(), primary_key=True),
        sa.Column("identity_kind", sa.Text(), primary_key=True),
        sa.Column("identity_value", sa.Text(), primary_key=True),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "identity_kind IN ('raw_match_id', 'source_sha256')",
            name="ck_match_review_verdicts_identity_kind_valid",
        ),
        sa.CheckConstraint(
            "verdict IN ('accepted', 'pending_review', 'rejected')",
            name="ck_match_review_verdicts_verdict_valid",
        ),
        schema="parser",
    )
    op.create_index(
        "ix_match_review_verdicts_source_sha256",
        "match_review_verdicts",
        ["source_sha256"],
        schema="parser",
    )

    op.execute(
        """
        INSERT INTO parser.match_review_verdicts
            (user_id, identity_kind, identity_value, source_sha256,
             verdict, review_reason)
        SELECT user_id,
               CASE WHEN raw_match_id IS NOT NULL
                    THEN 'raw_match_id' ELSE 'source_sha256' END,
               COALESCE(raw_match_id, sha256),
               sha256,
               review_status,
               review_reason
          FROM parser.matches
         WHERE review_status IN ('pending_review', 'rejected')
        ON CONFLICT (user_id, identity_kind, identity_value) DO UPDATE
            SET source_sha256 = EXCLUDED.source_sha256,
                verdict = EXCLUDED.verdict,
                review_reason = EXCLUDED.review_reason,
                updated_at = now()
        """
    )

    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON parser.match_review_verdicts TO deep_analysis_analytics;"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON parser.match_review_verdicts TO deep_analysis_parser;"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_match_review_verdicts_source_sha256",
        table_name="match_review_verdicts",
        schema="parser",
    )
    op.drop_table("match_review_verdicts", schema="parser")
