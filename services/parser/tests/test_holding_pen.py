"""Tests for the holding-pen behavior introduced in v0.9.8.

The consumer no longer drops partial parses outright (#75's Fix B);
instead it persists them with ``review_status='pending_review'`` so an
admin can decide. These tests cover:

* Empty parses (zero games) still drop on the floor.
* Partial parses (games present, no winners anywhere) land with
  ``review_status='pending_review'``.
* Conclusive parses (winner OR per-game winner) persist as
  ``review_status=NULL`` — same as v0.9.7.
* A later conclusive snapshot of the same logical match upgrades a
  ``pending_review`` row back to NULL (via _parse_quality_key + the
  persistence UPDATE path).
* An admin-rejected row is preserved across reparses (admin verdicts
  do not silently undo themselves).
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

import pytest
from parser_service.consumer import (
    ParserConsumer,
    _is_empty_parse,
    _is_partial_parse,
)
from parser_service.models import Match
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.persistence import persist_match
from sqlalchemy import select

# ---------------------------------------------------------------------------
# Pure helpers — no DB
# ---------------------------------------------------------------------------


class TestEmptyVsPartial:
    def test_empty_parse_no_games(self) -> None:
        assert _is_empty_parse(ParsedMatch()) is True
        assert _is_empty_parse(ParsedMatch(players=["alice", "bob"])) is True

    def test_partial_parse_games_no_winners(self) -> None:
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[ParsedGame(game_number=1, winner=None)],
        )
        assert _is_empty_parse(parsed) is False
        assert _is_partial_parse(parsed) is True

    def test_conclusive_parse_with_match_winner(self) -> None:
        parsed = ParsedMatch(
            players=["alice", "bob"],
            winner="alice",
            games=[ParsedGame(game_number=1, winner="alice")],
        )
        assert _is_empty_parse(parsed) is False
        assert _is_partial_parse(parsed) is False

    def test_real_draw_is_neither_empty_nor_partial(self) -> None:
        """Match-winner None but each game has a winner — that's a true
        Magic draw and must not be flagged."""
        parsed = ParsedMatch(
            players=["alice", "bob"],
            winner=None,
            games=[
                ParsedGame(game_number=1, winner="alice"),
                ParsedGame(game_number=2, winner="bob"),
                ParsedGame(game_number=3, winner=None, result="draw"),
            ],
        )
        assert _is_empty_parse(parsed) is False
        assert _is_partial_parse(parsed) is False


# ---------------------------------------------------------------------------
# Consumer-level: empty drops, partial → pending_review, conclusive → NULL
# ---------------------------------------------------------------------------


class _StubParser:
    """Test double — return the queued ``ParsedMatch`` from .parse()."""

    def __init__(self, parsed: ParsedMatch) -> None:
        self._parsed = parsed

    def parse(self, content: bytes) -> ParsedMatch:
        return self._parsed


def _consumer_with(parsed: ParsedMatch, sm, raw_root: Path) -> ParserConsumer:
    """Build a consumer using stub redis/parser dependencies.

    ``_resolve_hero`` is short-circuited: it queries ``auth.users``,
    which the parser test schema doesn't create. Letting the real
    impl run would poison the (shared) test session with an
    aborted-transaction state. The fallback returns
    ``parsed.players[0]`` — what the real path does too when the
    auth lookup misses, so behavior matches production for these
    tests.
    """

    class _DummyRedis:
        # The consumer needs *something* for the publisher constructor.
        def pubsub(self) -> Any:
            raise NotImplementedError

    consumer = ParserConsumer(
        redis_client=_DummyRedis(),
        sessionmaker=sm,
        raw_root=raw_root,
        parser=_StubParser(parsed),
        publisher=_NoopPublisher(),
    )

    async def _stub_resolve_hero(_user_id: int, players: list[str]) -> str | None:
        return str(players[0]) if players else None

    consumer._resolve_hero = _stub_resolve_hero
    return consumer


class _NoopPublisher:
    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        return None


def _write_raw(raw_root: Path, sha: str) -> None:
    """Write a non-empty raw file at the ingest shard path for ``sha``."""
    shard = raw_root / sha[0:2] / sha[2:4]
    shard.mkdir(parents=True, exist_ok=True)
    (shard / f"{sha}.dat").write_bytes(b"unused-by-stub-parser")


@pytest.mark.asyncio
async def test_consumer_drops_empty_parse(parser_session, tmp_path) -> None:
    sha = "e" * 64
    _write_raw(tmp_path, sha)
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(ParsedMatch(), sm, tmp_path)

    await consumer.handle_event(sha, user_id=1)

    rows = (await parser_session.execute(select(Match))).scalars().all()
    assert rows == [], "empty parse must drop, not persist"


@pytest.mark.asyncio
async def test_consumer_persists_partial_as_pending_review(parser_session, tmp_path) -> None:
    sha = "f" * 64
    _write_raw(tmp_path, sha)
    partial = ParsedMatch(
        raw_match_id="pending-uuid-1",
        players=["alice", "bob"],
        games=[ParsedGame(game_number=1, winner=None)],
    )
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(partial, sm, tmp_path)

    await consumer.handle_event(sha, user_id=1)
    parser_session.expire_all()

    row = (await parser_session.execute(select(Match))).scalar_one()
    assert row.review_status == "pending_review"
    assert row.raw_match_id == "pending-uuid-1"
    assert row.winner is None


@pytest.mark.asyncio
async def test_consumer_persists_conclusive_with_null_review_status(
    parser_session, tmp_path
) -> None:
    sha = "a" * 64
    _write_raw(tmp_path, sha)
    conclusive = ParsedMatch(
        raw_match_id="conclusive-uuid-1",
        players=["alice", "bob"],
        winner="alice",
        match_result="2-0",
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="alice"),
        ],
    )
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(conclusive, sm, tmp_path)

    await consumer.handle_event(sha, user_id=1)
    parser_session.expire_all()

    row = (await parser_session.execute(select(Match))).scalar_one()
    assert row.review_status is None
    assert row.winner == "alice"


# ---------------------------------------------------------------------------
# Persistence-level: pending_review → NULL on conclusive reparse,
# rejected survives reparse.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_review_upgrades_to_null_on_conclusive_reparse(parser_session) -> None:
    """The same logical match: first the agent ships a partial snapshot
    (caught mid-game), then later a conclusive snapshot. The second
    persist must UPDATE the existing row, including clearing
    ``review_status`` so the match becomes user-visible."""
    raw_id = "logical-uuid-1"
    sha_partial = "1" * 64
    sha_conclusive = "2" * 64

    partial = ParsedMatch(
        raw_match_id=raw_id,
        players=["alice", "bob"],
        games=[ParsedGame(game_number=1, winner=None)],
    )
    await persist_match(
        parser_session,
        partial,
        sha256=sha_partial,
        user_id=1,
        review_status="pending_review",
    )

    parser_session.expire_all()
    after_partial = (await parser_session.execute(select(Match))).scalar_one()
    assert after_partial.review_status == "pending_review"

    conclusive = ParsedMatch(
        raw_match_id=raw_id,
        players=["alice", "bob"],
        winner="alice",
        match_result="2-0",
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="alice"),
        ],
    )
    await persist_match(
        parser_session,
        conclusive,
        sha256=sha_conclusive,
        user_id=1,
        review_status=None,
    )

    parser_session.expire_all()
    after_conclusive = (await parser_session.execute(select(Match))).scalar_one()
    assert after_conclusive.id == after_partial.id, "logical identity preserved"
    assert after_conclusive.review_status is None, "upgraded back to user-visible"
    assert after_conclusive.winner == "alice"


@pytest.mark.asyncio
async def test_rejected_row_survives_conclusive_reparse(parser_session) -> None:
    """An admin's 'rejected' verdict must not be silently overturned by
    a later snapshot of the same logical match — even if that snapshot
    is conclusive."""
    raw_id = "logical-uuid-2"
    sha_a = "3" * 64
    sha_b = "4" * 64

    # Seed a rejected row directly (admin verdict happened in the UI).
    rejected = Match(
        id=uuid.uuid4(),
        sha256=sha_a,
        user_id=1,
        raw_match_id=raw_id,
        players=["alice", "bob"],
        winner=None,
        game_count=1,
        review_status="rejected",
    )
    parser_session.add(rejected)
    await parser_session.commit()

    conclusive = ParsedMatch(
        raw_match_id=raw_id,
        players=["alice", "bob"],
        winner="alice",
        match_result="2-0",
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="alice"),
        ],
    )
    await persist_match(
        parser_session,
        conclusive,
        sha256=sha_b,
        user_id=1,
        review_status=None,
    )

    parser_session.expire_all()
    survivor = (await parser_session.execute(select(Match))).scalar_one()
    assert survivor.review_status == "rejected", "admin rejection must survive"
    # Conclusive parse fields still update (winner, game_count) — the
    # admin's verdict applies to whether to surface the row, not to
    # whether to record what the parser saw.
    assert survivor.winner == "alice"
    assert survivor.game_count == 2


# ---------------------------------------------------------------------------
# Wrappers — share the session-maker adapter pattern from
# test_cleanup_71_collision.
# ---------------------------------------------------------------------------


def _session_maker_returning(session):
    """Adapt the test's session into something the consumer can ``async with``."""

    class _Wrapper:
        def __call__(self):
            return _Ctx(session)

    class _Ctx:
        def __init__(self, s):
            self._s = s

        async def __aenter__(self):
            return self._s

        async def __aexit__(self, *exc):
            return False

    return _Wrapper()


# Make pytest-asyncio understand the asyncio default loop scope.
@pytest.fixture(autouse=True)
def _ensure_loop_policy() -> None:
    # Some runners need the policy explicitly set when there is no
    # surrounding event loop fixture; this is harmless when one exists.
    asyncio.get_event_loop_policy()
