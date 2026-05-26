"""Tests for the backfill scanner (``parser_service.backfill``).

Verifies that the unparsed-files query processes newest uploads first so
that when the same logical match has multiple snapshots (partial
mid-match + complete post-match), the complete one is parsed first and
the quality gate correctly discards the partials.
"""

from __future__ import annotations


def test_unparsed_sql_orders_newest_first() -> None:
    """The backfill SQL must ORDER BY upload timestamp descending so that
    the newest snapshot of a match is processed before older partials."""
    from parser_service.backfill import _UNPARSED_SQL

    sql = _UNPARSED_SQL.text.lower()
    assert "order by" in sql, "_UNPARSED_SQL is missing ORDER BY clause"
    # Verify it orders by the most recent upload time, descending.
    assert "max(u.uploaded_at)" in sql, "_UNPARSED_SQL should order by MAX(u.uploaded_at)"
    assert "desc" in sql.split("order by")[1], "_UNPARSED_SQL ORDER BY must be DESC (newest first)"


def test_unparsed_sql_uses_group_by() -> None:
    """GROUP BY is required for the aggregate ORDER BY to work."""
    from parser_service.backfill import _UNPARSED_SQL

    sql = _UNPARSED_SQL.text.lower()
    assert "group by u.sha256, u.user_id" in sql, "_UNPARSED_SQL must GROUP BY u.sha256, u.user_id"
