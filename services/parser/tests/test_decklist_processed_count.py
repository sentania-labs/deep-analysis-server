"""Regression tests for issue #147: the decklist backfill counter.

``ParserConsumer.handle_decklist_event`` used to be typed ``-> None`` on
every path, including success, while ``scan_unparsed`` counted processed
items with ``if result is not None``. The decklist branch of that counter
was therefore dead: a batch that parsed 50 decklists logged
``processed=0``.

These tests drive the *real* ``handle_decklist_event`` (only its external
edges are stubbed) so they fail against the old ``-> None`` contract
rather than against a mock's stand-in return value.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from parser_service.consumer import ParserConsumer
from parser_service.storage import RawFileNotFoundError, RawFileTooLargeError

from common.storage import ObjectStorageError

SAMPLE_DECK_XML = b"""\
<CardGrouping Name="Legacy Reanimator" NetDeckId="111106631"
              GroupingType="Deck" FormatCode="CLEGACY"
              Timestamp="2026-05-17T23:10:30.413Z">
  <Item CatId="30302" Quantity="1" IsSideboard="false" Annotation="0" />
  <Item CatId="35118" Quantity="4" IsSideboard="false" Annotation="0" />
</CardGrouping>
"""


class _FakeSession:
    """Minimal async session: enough for the persist path and rollback."""

    def __init__(self) -> None:
        self.rolled_back = False

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    async def rollback(self) -> None:
        self.rolled_back = True


def _make_consumer() -> ParserConsumer:
    sm = MagicMock(side_effect=lambda: _FakeSession())
    consumer = ParserConsumer(
        redis_client=MagicMock(),
        sessionmaker=sm,
        store=MagicMock(),
        publisher=MagicMock(),
    )
    # _lookup_original_filename issues its own query; it is not under test.
    consumer._lookup_original_filename = AsyncMock(return_value="deck.dat")
    return consumer


# ---------------------------------------------------------------------------
# handle_decklist_event return contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_decklist_event_returns_true_on_success() -> None:
    """A parsed and persisted decklist must report that work was done."""
    consumer = _make_consumer()

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(return_value=SAMPLE_DECK_XML)),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()) as persist,
    ):
        result = await consumer.handle_decklist_event("abc123", 1)

    assert result is True, (
        "handle_decklist_event must return True on success so scan_unparsed can count it"
    )
    persist.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw_error",
    [
        RawFileNotFoundError("missing"),
        RawFileTooLargeError("too big"),
        ObjectStorageError("store down"),
        OSError("read failed"),
    ],
    ids=["missing", "too-large", "storage-error", "oserror"],
)
async def test_handle_decklist_event_returns_false_when_raw_unreadable(
    raw_error: Exception,
) -> None:
    """Every raw-read skip path is a no-op and must not be counted."""
    consumer = _make_consumer()

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(side_effect=raw_error)),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()) as persist,
    ):
        result = await consumer.handle_decklist_event("abc123", 1)

    assert result is False
    persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_decklist_event_returns_false_on_unparseable_xml() -> None:
    """Garbage XML is a no-op and must not be counted."""
    consumer = _make_consumer()

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(return_value=b"<not valid xml")),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()) as persist,
    ):
        result = await consumer.handle_decklist_event("abc123", 1)

    assert result is False
    persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_decklist_event_returns_false_on_persist_failure() -> None:
    """A rolled-back persist did no work and must not be counted."""
    consumer = _make_consumer()

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(return_value=SAMPLE_DECK_XML)),
        patch(
            "parser_service.consumer.persist_deck_composition",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
    ):
        result = await consumer.handle_decklist_event("abc123", 1)

    assert result is False


# ---------------------------------------------------------------------------
# End-to-end through scan_unparsed with the real handler
# ---------------------------------------------------------------------------


def _make_scan_sessionmaker(match_rows: list[Any], deck_rows: list[Any]) -> MagicMock:
    """Sessionmaker for scan_unparsed: match rows first, then deck rows."""
    call_count = 0

    class _FakeResult:
        def __init__(self, rows: list[Any]) -> None:
            self._rows = rows

        def all(self) -> list[Any]:
            return self._rows

    class _ScanSession:
        async def __aenter__(self) -> _ScanSession:
            return self

        async def __aexit__(self, *args: object) -> None:
            pass

        async def execute(self, stmt: object, params: object = None) -> _FakeResult:
            nonlocal call_count
            idx = call_count
            call_count += 1
            return _FakeResult(match_rows if idx == 0 else deck_rows)

        async def rollback(self) -> None:
            pass

    return MagicMock(side_effect=lambda: _ScanSession())


@pytest.mark.asyncio
async def test_scan_unparsed_counts_real_decklist_successes() -> None:
    """A decklist batch reports a processed count matching what was parsed.

    This is the issue #147 regression: with ``handle_decklist_event``
    returning ``None`` on success, this returned 0.
    """
    from parser_service.backfill import scan_unparsed

    consumer = _make_consumer()
    sm = _make_scan_sessionmaker(
        match_rows=[],
        deck_rows=[("sha1", 1), ("sha2", 2), ("sha3", 3)],
    )

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(return_value=SAMPLE_DECK_XML)),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()),
        patch("parser_service.backfill.get_settings") as mock_settings,
    ):
        mock_settings.return_value.backfill_batch_size = 50
        result = await scan_unparsed(sm, consumer, batch_size=50)

    assert result == 3


@pytest.mark.asyncio
async def test_scan_unparsed_does_not_count_skipped_or_failed_decklists() -> None:
    """Only the decklist that actually persisted is counted."""
    from parser_service.backfill import scan_unparsed

    consumer = _make_consumer()
    sm = _make_scan_sessionmaker(
        match_rows=[],
        deck_rows=[("missing_sha", 1), ("garbage_sha", 2), ("good_sha", 3)],
    )

    async def _fake_read_raw(store: object, sha256: str, **kwargs: object) -> bytes:
        if sha256 == "missing_sha":
            raise RawFileNotFoundError(sha256)
        if sha256 == "garbage_sha":
            return b"<not valid xml"
        return SAMPLE_DECK_XML

    with (
        patch("parser_service.consumer.read_raw", _fake_read_raw),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()),
        patch("parser_service.backfill.get_settings") as mock_settings,
    ):
        mock_settings.return_value.backfill_batch_size = 50
        result = await scan_unparsed(sm, consumer, batch_size=50)

    assert result == 1, "a skipped and an unparseable decklist must not be counted"
