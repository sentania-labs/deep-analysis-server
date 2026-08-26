"""Tests for the backfill scanner (``parser_service.backfill``).

Verifies that the unparsed-files query processes newest uploads first so
that when the same logical match has multiple snapshots (partial
mid-match + complete post-match), the complete one is parsed first and
the quality gate correctly discards the partials.

Also verifies that the decklist backfill query is correct and that
``scan_unparsed`` processes both match logs and decklists.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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


# ---------------------------------------------------------------------------
# Decklist backfill SQL structure tests
# ---------------------------------------------------------------------------


def test_unparsed_decklists_sql_targets_decklist_content_type() -> None:
    """The decklist backfill query must filter on content_type = 'decklist'."""
    from parser_service.backfill import _UNPARSED_DECKLISTS_SQL

    sql = _UNPARSED_DECKLISTS_SQL.text.lower()
    assert "content_type = 'decklist'" in sql, (
        "_UNPARSED_DECKLISTS_SQL must filter on content_type = 'decklist'"
    )


def test_unparsed_decklists_sql_joins_deck_compositions() -> None:
    """The decklist backfill query must LEFT JOIN parser.deck_compositions."""
    from parser_service.backfill import _UNPARSED_DECKLISTS_SQL

    sql = _UNPARSED_DECKLISTS_SQL.text.lower()
    assert "parser.deck_compositions" in sql, (
        "_UNPARSED_DECKLISTS_SQL must join against parser.deck_compositions"
    )
    assert "left join" in sql, "_UNPARSED_DECKLISTS_SQL must use LEFT JOIN"
    assert "d.id is null" in sql, (
        "_UNPARSED_DECKLISTS_SQL must check d.id IS NULL to find unprocessed decklists"
    )


def test_unparsed_decklists_sql_orders_newest_first() -> None:
    """The decklist backfill query must ORDER BY newest first."""
    from parser_service.backfill import _UNPARSED_DECKLISTS_SQL

    sql = _UNPARSED_DECKLISTS_SQL.text.lower()
    assert "order by" in sql, "_UNPARSED_DECKLISTS_SQL is missing ORDER BY clause"
    assert "desc" in sql.split("order by")[1], (
        "_UNPARSED_DECKLISTS_SQL ORDER BY must be DESC (newest first)"
    )


def test_unparsed_decklists_sql_uses_group_by() -> None:
    """GROUP BY is required for the aggregate ORDER BY to work."""
    from parser_service.backfill import _UNPARSED_DECKLISTS_SQL

    sql = _UNPARSED_DECKLISTS_SQL.text.lower()
    assert "group by u.sha256, u.user_id" in sql, (
        "_UNPARSED_DECKLISTS_SQL must GROUP BY u.sha256, u.user_id"
    )


# ---------------------------------------------------------------------------
# scan_unparsed integration tests (mocked DB + consumer)
# ---------------------------------------------------------------------------


def _make_mock_session(match_rows: list, deck_rows: list) -> MagicMock:
    """Build a mock async_sessionmaker that returns match rows on the
    first call and deck rows on the second call."""
    call_count = 0

    class _FakeResult:
        def __init__(self, rows: list) -> None:
            self._rows = rows

        def all(self) -> list:
            return self._rows

    class _FakeSession:
        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def execute(self, stmt: object, params: object = None) -> _FakeResult:
            nonlocal call_count
            idx = call_count
            call_count += 1
            if idx == 0:
                return _FakeResult(match_rows)
            return _FakeResult(deck_rows)

    return MagicMock(side_effect=lambda: _FakeSession())


@pytest.mark.asyncio
async def test_scan_unparsed_processes_decklists() -> None:
    """scan_unparsed should call handle_decklist_event for decklist rows."""
    from parser_service.backfill import scan_unparsed

    consumer = AsyncMock()
    consumer.handle_event = AsyncMock(return_value=MagicMock())
    consumer.handle_decklist_event = AsyncMock()

    sm = _make_mock_session(
        match_rows=[("abc123", 1, None)],
        deck_rows=[("def456", 2)],
    )

    with patch("parser_service.backfill.get_settings") as mock_settings:
        mock_settings.return_value.backfill_batch_size = 50
        result = await scan_unparsed(sm, consumer, batch_size=50)

    assert result == 2
    consumer.handle_event.assert_called_once_with("abc123", 1, agent_classification=None)
    consumer.handle_decklist_event.assert_called_once_with("def456", 2)


@pytest.mark.asyncio
async def test_scan_unparsed_only_decklists() -> None:
    """scan_unparsed should work when only decklists need processing."""
    from parser_service.backfill import scan_unparsed

    consumer = AsyncMock()
    consumer.handle_event = AsyncMock(return_value=MagicMock())
    consumer.handle_decklist_event = AsyncMock()

    sm = _make_mock_session(
        match_rows=[],
        deck_rows=[("def456", 2), ("ghi789", 3)],
    )

    with patch("parser_service.backfill.get_settings") as mock_settings:
        mock_settings.return_value.backfill_batch_size = 50
        result = await scan_unparsed(sm, consumer, batch_size=50)

    assert result == 2
    consumer.handle_event.assert_not_called()
    assert consumer.handle_decklist_event.call_count == 2


@pytest.mark.asyncio
async def test_scan_unparsed_nothing_to_do() -> None:
    """scan_unparsed returns 0 when no match logs or decklists need processing."""
    from parser_service.backfill import scan_unparsed

    consumer = AsyncMock()
    consumer.handle_event = AsyncMock()
    consumer.handle_decklist_event = AsyncMock()

    sm = _make_mock_session(match_rows=[], deck_rows=[])

    with patch("parser_service.backfill.get_settings") as mock_settings:
        mock_settings.return_value.backfill_batch_size = 50
        result = await scan_unparsed(sm, consumer, batch_size=50)

    assert result == 0
    consumer.handle_event.assert_not_called()
    consumer.handle_decklist_event.assert_not_called()


@pytest.mark.asyncio
async def test_scan_unparsed_decklist_error_does_not_stop_processing() -> None:
    """A failed decklist parse should not prevent other decklists from being processed."""
    from parser_service.backfill import scan_unparsed

    consumer = AsyncMock()
    consumer.handle_event = AsyncMock(return_value=MagicMock())
    # The second call is the *successful* one, so its stand-in return value has
    # to be something scan_unparsed counts (it counts `is not None`). A bare
    # `None` here meant "second decklist also did nothing", which is why this
    # asserted 1 and got 0 (issue #145). Matches the mock shape used by
    # test_scan_unparsed_processes_decklists above.
    #
    # Both mocks overstate reality: the real handle_decklist_event is typed
    # `-> None`, so scan_unparsed's decklist counter is dead in production.
    # That is issue #147; these tests assert the intended counting behavior.
    consumer.handle_decklist_event = AsyncMock(
        side_effect=[RuntimeError("boom"), MagicMock()],
    )

    sm = _make_mock_session(
        match_rows=[],
        deck_rows=[("fail_sha", 1), ("ok_sha", 2)],
    )

    with patch("parser_service.backfill.get_settings") as mock_settings:
        mock_settings.return_value.backfill_batch_size = 50
        result = await scan_unparsed(sm, consumer, batch_size=50)

    # Only the second decklist succeeds.
    assert result == 1
    assert consumer.handle_decklist_event.call_count == 2
