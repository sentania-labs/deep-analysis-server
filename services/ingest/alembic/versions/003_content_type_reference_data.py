"""Add 'reference-data' to game_log_files content_type check constraint.

Revision ID: 003
Revises: 002
Create Date: 2026-05-18

The agent now ships CardDataSource XML files as ``reference-data``.
The existing check constraint only allows ``match-log``, ``decklist``,
and ``unknown``.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_game_log_files_content_type",
        "game_log_files",
        schema="ingest",
    )
    op.create_check_constraint(
        "ck_game_log_files_content_type",
        "game_log_files",
        "content_type IN ('match-log', 'decklist', 'reference-data', 'unknown')",
        schema="ingest",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_game_log_files_content_type",
        "game_log_files",
        schema="ingest",
    )
    op.create_check_constraint(
        "ck_game_log_files_content_type",
        "game_log_files",
        "content_type IN ('match-log', 'decklist', 'unknown')",
        schema="ingest",
    )
