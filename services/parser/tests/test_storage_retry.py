"""Tests for the bounded storage-retry path introduced in #158.

``ParserConsumer`` used to swallow a transient object-store error and
return, leaving only a log line behind. It now keeps a per-file retry
schedule (capped, jittered exponential backoff) for a bounded window
from the first failure, and only after that window does the file fail
visibly: a holding-pen row with a storage-outage reason plus a counter
on the metrics endpoint.

Everything here runs on an injected clock, so no test waits in real time.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from parser_service.consumer import ParserConsumer
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.settings import ParserSettings
from parser_service.storage import RawFileNotFoundError, RawFileTooLargeError
from prometheus_client import REGISTRY

from common.storage import ObjectStorageError

SAMPLE_DECK_XML = b"""\
<CardGrouping Name="Test Deck" NetDeckId="111106631"
              GroupingType="Deck" FormatCode="CLEGACY"
              Timestamp="2026-05-17T23:10:30.413Z">
  <Item CatId="30302" Quantity="1" IsSideboard="false" Annotation="0" />
</CardGrouping>
"""

# The three retry knobs, mirroring the settings defaults.
_WINDOW = 86_400.0
_BASE = 1.0
_CAP = 60.0

RETRIES_COUNTER = "parser_storage_retries_total"
GIVEUPS_COUNTER = "parser_storage_giveups_total"

_CONSUME_PATCHES = (
    "parser_service.consumer.persist_match",
    "parser_service.consumer.link_deck_to_match",
    "parser_service.consumer.analytics_client.classify_with_confidence",
)


class _Clock:
    """Manually advanced monotonic clock — no real waiting anywhere."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _FakeSession:
    """Minimal async session for the calls the consumer makes."""

    def __init__(self) -> None:
        self.rolled_back = False
        self.executed: list[tuple[Any, Any]] = []
        self.committed = 0

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    async def execute(self, stmt: Any, params: Any = None) -> Any:
        self.executed.append((stmt, params))
        return MagicMock(scalar_one_or_none=lambda: None, all=lambda: [])

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolled_back = True


def _settings() -> ParserSettings:
    return ParserSettings(
        service_name="parser",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
        jwt_public_key_path="keys/jwt_public.pem",
    )


def _match_parse() -> ParsedMatch:
    return ParsedMatch(
        raw_match_id="logical-uuid-1",
        players=["alice", "bob"],
        winner="alice",
        match_result="2-0",
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="alice"),
        ],
    )


def _make_consumer(
    session: _FakeSession | None = None,
    clock: _Clock | None = None,
    parser: Any = None,
) -> ParserConsumer:
    sm = MagicMock(side_effect=lambda: session or _FakeSession())
    return ParserConsumer(
        redis_client=MagicMock(),
        sessionmaker=sm,
        store=MagicMock(),
        parser=parser,
        publisher=AsyncMock(),
        clock=clock or _Clock(),
    )


def _counter(name: str) -> float:
    value = REGISTRY.get_sample_value(name)
    assert value is not None, f"{name} is not registered"
    return value


def _stmt_text(stmt: Any) -> str:
    """The SQL string of a ``text()`` clause or a plain string."""
    return getattr(stmt, "text", stmt)


def _store_error() -> None:
    raise ObjectStorageError("connect timeout")


# ---------------------------------------------------------------------------
# 1. Transient error, then success → parsed exactly once
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transient_error_then_success_parses_once() -> None:
    """The retry defers, the next attempt parses, and nothing parses twice."""
    clock = _Clock()
    parser = MagicMock()
    parser.parse.return_value = _match_parse()
    consumer = _make_consumer(_FakeSession(), clock, parser)
    sha = "a" * 64

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=[ObjectStorageError("connect timeout"), b"raw bytes"]),
        ) as read,
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
        patch("parser_service.consumer.persist_match", AsyncMock(return_value=_match_row())),
        patch("parser_service.consumer.link_deck_to_match", AsyncMock(return_value=None)),
    ):
        first = await consumer.handle_event(sha, 1)
        assert first is None, "the deferred attempt reports no parse result"
        assert len(consumer._retry_state) == 1, "the file is queued for retry"

        clock.advance(_BASE)
        second = await consumer.handle_event(sha, 1)

    assert read.await_count == 2
    parser.parse.assert_called_once()
    assert isinstance(second, ParsedMatch)
    assert second.winner == "alice"
    assert consumer._retry_state == {}, "a resolved file leaves the retry table"


def _match_row() -> Any:
    row = SimpleNamespace()
    row.id = "m1"
    row.format = "Legacy"
    row.format_source = None
    row.archetype_id = None
    return row


# ---------------------------------------------------------------------------
# 2. Repeated errors back off
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attempts", "advance"),
    [(1, _BASE), (2, _BASE * 2), (3, _BASE * 4), (7, _CAP)],
)
async def test_repeated_failures_back_off_exponentially_to_the_cap(
    attempts: int,
    advance: float,
) -> None:
    """Each failure reschedules within ``min(cap, base * 2**(n-1))``."""
    clock = _Clock()
    consumer = _make_consumer(clock=clock)
    sha = "b" * 64
    before = _counter(RETRIES_COUNTER)
    delays: list[float] = []

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        for _ in range(attempts):
            await consumer.handle_event(sha, 1)
            record = consumer._retry_state[(sha, 1)]
            delays.append(record.due_at - clock.now)
            clock.advance(advance)

    assert record.attempts == attempts
    assert record.first_failure == 0.0, "the window is stamped on the first failure only"
    for index, delay in enumerate(delays):
        bound = min(_CAP, _BASE * (2**index))
        assert 0.0 <= delay <= bound, f"attempt {index + 1}: jittered {delay} not in 0..{bound}"
    assert _counter(RETRIES_COUNTER) - before == attempts


@pytest.mark.asyncio
@pytest.mark.parametrize("prior_attempts", [1023, 1024, 1025, 100000])
async def test_huge_attempt_counts_keep_the_delay_finite(prior_attempts: int) -> None:
    """2**n saturates the float range, so the exponent must be bounded."""
    from parser_service.consumer import _MAX_BACKOFF_EXPONENT, _RetryRecord

    clock = _Clock()
    consumer = _make_consumer(clock=clock)
    sha = "4" * 64
    consumer._retry_state[(sha, 1)] = _RetryRecord(
        first_failure=0.0,
        attempts=prior_attempts,
        due_at=0.0,
        kind="match-log",
    )

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        await consumer.handle_event(sha, 1)

    record = consumer._retry_state[(sha, 1)]
    assert record.attempts == prior_attempts + 1
    delay = record.due_at - clock.now
    assert delay == delay, "the jittered delay must be a finite float"
    assert 0.0 <= delay <= _CAP
    assert _MAX_BACKOFF_EXPONENT == 1023


@pytest.mark.asyncio
async def test_backoff_never_exceeds_the_cap_across_many_failures() -> None:
    """After enough failures the interval saturates at the cap."""
    clock = _Clock()
    consumer = _make_consumer(clock=clock)
    sha = "c" * 64

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        for _ in range(12):
            await consumer.handle_event(sha, 1)
            record = consumer._retry_state[(sha, 1)]
            assert record.due_at - clock.now <= _CAP + 1e-9
            clock.advance(_CAP)

    assert record.attempts == 12


# ---------------------------------------------------------------------------
# 3. Window exhausted → holding pen + give-up counter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_window_exhausted_lands_in_holding_pen_and_counts() -> None:
    """Past the window the file gets a ``pending_review`` row and one give-up."""
    clock = _Clock()
    session = _FakeSession()
    consumer = _make_consumer(session, clock)
    sha = "d" * 64
    giveups_before = _counter(GIVEUPS_COUNTER)
    retries_before = _counter(RETRIES_COUNTER)

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        await consumer.handle_event(sha, 7)
        clock.advance(_WINDOW)
        assert await consumer.handle_event(sha, 7) is None

    assert consumer._retry_state == {}, "the give-up clears the retry table"
    holds = [(_stmt_text(s), p) for s, p in session.executed]
    assert holds, "the give-up must write a holding-pen row"
    _stmt, params = holds[-1]
    assert params["sha"] == sha
    assert params["user_id"] == 7
    assert params["reason"].startswith("storage outage:")
    assert session.committed == 1
    assert _counter(GIVEUPS_COUNTER) - giveups_before == 1, "one give-up per file"
    # The boundary call is the give-up itself, so exactly one deferred
    # attempt was counted for this file.
    assert _counter(RETRIES_COUNTER) - retries_before == 1


@pytest.mark.asyncio
async def test_same_content_for_two_users_is_retried_and_held_per_user() -> None:
    """Retry state follows the (sha, user) parse identity, not the sha alone."""
    clock = _Clock()
    session = _FakeSession()
    consumer = _make_consumer(session, clock)
    sha = "e" * 64

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        await consumer.handle_event(sha, 3)
        await consumer.handle_event(sha, 4)
        assert set(consumer._retry_state) == {(sha, 3), (sha, 4)}
        clock.advance(_WINDOW)
        await consumer.handle_event(sha, 3)
        await consumer.handle_event(sha, 4)

    assert consumer._retry_state == {}
    assert sorted(params["user_id"] for _s, params in session.executed) == [3, 4]


@pytest.mark.asyncio
async def test_decklist_give_up_counts_but_writes_no_match_row() -> None:
    """A decklist sha is not a match: no phantom holding-pen row."""
    clock = _Clock()
    session = _FakeSession()
    consumer = _make_consumer(session, clock)
    sha = "9" * 64
    giveups_before = _counter(GIVEUPS_COUNTER)

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        assert await consumer.handle_decklist_event(sha, 4) is False
        clock.advance(_WINDOW)
        assert await consumer.handle_decklist_event(sha, 4) is False

    assert consumer._retry_state == {}
    assert session.executed == [], "decklist give-up must not touch parser.matches"
    assert _counter(GIVEUPS_COUNTER) - giveups_before == 1


@pytest.mark.asyncio
async def test_unexpected_error_in_a_retry_does_not_escape_the_drain() -> None:
    """A retried parse that blows up is logged and dropped, not fatal."""
    clock = _Clock()
    consumer = _make_consumer(_FakeSession(), clock)
    sha = "8" * 64
    calls = {"n": 0}

    def _read(*_a: object, **_kw: object) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ObjectStorageError("blip")
        raise RuntimeError("boom")

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(side_effect=_read)),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        await consumer.handle_event(sha, 1)
        clock.advance(_BASE * 10)
        await consumer._drain_due_retries()

    assert consumer._retry_state == {}, "the failed retry is dropped for the backfill scan"
    assert calls["n"] == 2


# ---------------------------------------------------------------------------
# Non-transient errors keep their existing handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw_error", "retried"),
    [
        (RawFileNotFoundError("missing"), False),
        (RawFileTooLargeError("too big"), False),
        (ObjectStorageError("store down"), True),
        (OSError("read failed"), True),
    ],
    ids=["missing", "too-large", "storage-error", "oserror"],
)
async def test_only_transient_errors_are_queued_for_retry(
    raw_error: Exception,
    retried: bool,
) -> None:
    """A missing object or oversized object is not backed off; a blip is."""
    consumer = _make_consumer(clock=_Clock())

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(side_effect=raw_error)),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()) as persist,
    ):
        assert await consumer.handle_decklist_event("f" * 64, 1) is False

    assert (len(consumer._retry_state) == 1) is retried
    persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_decklist_transient_error_then_success_parses_once() -> None:
    """The decklist path shares the retry table and resolves in one parse."""
    clock = _Clock()
    consumer = _make_consumer(_FakeSession(), clock)
    consumer._lookup_original_filename = AsyncMock(return_value="deck.dat")
    sha = "9" * 64

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=[ObjectStorageError("blip"), SAMPLE_DECK_XML]),
        ) as read,
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
        patch("parser_service.consumer.persist_deck_composition", AsyncMock()) as persist,
    ):
        assert await consumer.handle_decklist_event(sha, 1) is False
        assert len(consumer._retry_state) == 1
        clock.advance(_BASE)
        assert await consumer.handle_decklist_event(sha, 1) is True

    assert read.await_count == 2
    persist.assert_awaited_once()
    assert consumer._retry_state == {}


@pytest.mark.asyncio
async def test_retry_is_not_re_attempted_before_its_due_time() -> None:
    """The due-time gate means one store call per elapsed backoff."""
    clock = _Clock()
    parser = MagicMock()
    parser.parse.return_value = _match_parse()
    consumer = _make_consumer(_FakeSession(), clock, parser)
    sha = "1" * 64

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=[ObjectStorageError("blip"), b"raw"]),
        ) as read,
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
        patch("parser_service.consumer.persist_match", AsyncMock(return_value=_match_row())),
        patch("parser_service.consumer.link_deck_to_match", AsyncMock(return_value=None)),
    ):
        await consumer.handle_event(sha, 1)
        due = consumer._retry_state[(sha, 1)].due_at
        assert due >= clock.now
        # Same clock value: not due yet, so no second store call.
        assert await consumer.handle_event(sha, 1) is None
        assert read.await_count == 1
        clock.advance(max(0.001, due - clock.now))
        await consumer._drain_due_retries()

    assert read.await_count == 2, "the drain re-attempts a file whose backoff elapsed"
    assert consumer._retry_state == {}


# ---------------------------------------------------------------------------
# The loop drives retries without an inline sleep
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_loop_drains_due_retries_between_messages() -> None:
    """A deferred file is re-attempted by the consumer loop, not a sleep."""
    clock = _Clock()
    parser = MagicMock()
    parser.parse.return_value = _match_parse()
    consumer = _make_consumer(_FakeSession(), clock, parser)
    sha = "2" * 64

    class _Pubsub:
        def __init__(self) -> None:
            self.polls = 0

        async def subscribe(self, *_a: object, **_kw: object) -> None:
            return None

        async def unsubscribe(self, *_a: object, **_kw: object) -> None:
            return None

        async def aclose(self) -> None:
            return None

        async def get_message(self, **_kw: object) -> dict[str, Any] | None:
            self.polls += 1
            if self.polls == 1:
                return {
                    "data": '{"sha256": "' + sha + '", "user_id": 1, "content_type": "match-log"}'
                }
            # Second poll: the backoff has elapsed by the injected clock,
            # so the None tick must run the queued retry. Third poll stops.
            clock.advance(_BASE)
            if self.polls >= 3:
                consumer.stop()
            return None

    pubsub = _Pubsub()
    redis_client = MagicMock()
    redis_client.pubsub.return_value = pubsub
    consumer._redis = redis_client
    consumer._resolve_hero = AsyncMock(return_value="alice")

    def _read(*_a: object, **_kw: object) -> bytes:
        record = consumer._retry_state[(sha, 1)]
        if record.attempts == 0:
            raise ObjectStorageError("blip")
        return b"raw"

    with (
        patch("parser_service.consumer.read_raw", AsyncMock(side_effect=_read)),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
        patch("parser_service.consumer.persist_match", AsyncMock(return_value=_match_row())),
        patch("parser_service.consumer.link_deck_to_match", AsyncMock(return_value=None)),
    ):
        await consumer.run()

    assert consumer._retry_state == {}, "the loop resolved the deferred file"
    assert parser.parse.call_count == 1, "exactly one parse for one file"


@pytest.mark.asyncio
async def test_hold_row_written_to_the_database(parser_session) -> None:
    """Against a real Postgres the give-up row is readable in the pen."""
    clock = _Clock()
    session = parser_session
    consumer = ParserConsumer(
        redis_client=MagicMock(),
        sessionmaker=lambda: session,
        store=MagicMock(),
        clock=clock,
    )
    sha = "3" * 64

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        await consumer.handle_event(sha, 11)
        clock.advance(_WINDOW)
        await consumer.handle_event(sha, 11)

    from parser_service.models import Match
    from sqlalchemy import select

    rows = (await parser_session.execute(select(Match).where(Match.sha256 == sha))).scalars().all()
    assert len(rows) == 1, "the give-up is one row per (sha256, user_id)"
    assert rows[0].review_status == "pending_review"
    assert rows[0].review_reason is not None
    assert rows[0].review_reason.startswith("storage outage:")


@pytest.mark.asyncio
async def test_hold_row_never_overwrites_an_existing_match(parser_session) -> None:
    """A give-up on a sha that already has a row leaves that row untouched."""
    from parser_service.models import Match
    from sqlalchemy import select

    clock = _Clock()
    session = parser_session
    sha = "4" * 64
    session.add(
        Match(
            id=uuid.uuid4(),
            sha256=sha,
            user_id=12,
            game_count=2,
            review_status="rejected",
            review_reason="admin said no",
        )
    )
    await session.commit()
    consumer = ParserConsumer(
        redis_client=MagicMock(),
        sessionmaker=lambda: session,
        store=MagicMock(),
        clock=clock,
    )

    with (
        patch(
            "parser_service.consumer.read_raw",
            AsyncMock(side_effect=lambda *a, **kw: _store_error()),
        ),
        patch("parser_service.consumer.get_parser_settings", return_value=_settings()),
    ):
        await consumer.handle_event(sha, 12)
        clock.advance(_WINDOW)
        await consumer.handle_event(sha, 12)

    row = (await session.execute(select(Match).where(Match.sha256 == sha))).scalar_one()
    assert row.review_status == "rejected"
    assert row.review_reason == "admin said no"
    assert row.game_count == 2
