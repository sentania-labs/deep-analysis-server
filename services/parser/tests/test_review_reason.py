"""Tests for the review_reason feature.

When a parse is held for review (``review_status='pending_review'``),
the consumer sets a human-readable ``review_reason`` string explaining
why. These tests cover:

* ``_build_review_reason`` produces the expected strings.
* Consumer-level: partial parses land with both ``review_status`` and
  ``review_reason`` set.
* Consumer-level: conclusive parses have ``review_reason=NULL``.
* Persistence-level: a conclusive reparse clears ``review_reason``
  alongside ``review_status``.
* Persistence-level: an admin-rejected row keeps its ``review_reason``
  across reparses.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

import pytest
from parser_service.consumer import (
    ParserConsumer,
    _build_review_reason,
)
from parser_service.models import Match
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.persistence import persist_match
from sqlalchemy import select

# ---------------------------------------------------------------------------
# Pure unit tests — _build_review_reason
# ---------------------------------------------------------------------------


class TestBuildReviewReason:
    def test_single_game_no_winners(self) -> None:
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[ParsedGame(game_number=1, winner=None)],
        )
        reason = _build_review_reason(parsed)
        assert "No game winners resolved" in reason
        assert "1 game observed" in reason

    def test_multiple_games_no_winners(self) -> None:
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[
                ParsedGame(game_number=1, winner=None),
                ParsedGame(game_number=2, winner=None),
                ParsedGame(game_number=3, winner=None),
            ],
        )
        reason = _build_review_reason(parsed)
        assert "No game winners resolved" in reason
        assert "3 games observed" in reason

    def test_plural_vs_singular(self) -> None:
        one_game = ParsedMatch(
            games=[ParsedGame(game_number=1, winner=None)],
        )
        two_games = ParsedMatch(
            games=[
                ParsedGame(game_number=1, winner=None),
                ParsedGame(game_number=2, winner=None),
            ],
        )
        assert "1 game observed" in _build_review_reason(one_game)
        assert "2 games observed" in _build_review_reason(two_games)


# ---------------------------------------------------------------------------
# Consumer-level: review_reason set on partial, absent on conclusive
# ---------------------------------------------------------------------------


class _StubParser:
    def __init__(self, parsed: ParsedMatch) -> None:
        self._parsed = parsed

    def parse(self, content: bytes) -> ParsedMatch:
        return self._parsed


class _NoopPublisher:
    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        return None


def _session_maker_returning(session: Any) -> Any:
    class _Wrapper:
        def __call__(self) -> Any:
            return _Ctx(session)

    class _Ctx:
        def __init__(self, s: Any) -> None:
            self._s = s

        async def __aenter__(self) -> Any:
            return self._s

        async def __aexit__(self, *exc: Any) -> bool:
            return False

    return _Wrapper()


def _write_raw(raw_root: Path, sha: str) -> None:
    shard = raw_root / sha[0:2] / sha[2:4]
    shard.mkdir(parents=True, exist_ok=True)
    (shard / f"{sha}.dat").write_bytes(b"unused-by-stub-parser")


def _consumer_with(parsed: ParsedMatch, sm: Any, raw_root: Path) -> ParserConsumer:
    class _DummyRedis:
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


@pytest.mark.asyncio
async def test_consumer_sets_review_reason_on_partial(parser_session: Any, tmp_path: Path) -> None:
    sha = "d" * 64
    _write_raw(tmp_path, sha)
    partial = ParsedMatch(
        raw_match_id="reason-uuid-1",
        players=["alice", "bob"],
        games=[
            ParsedGame(game_number=1, winner=None),
            ParsedGame(game_number=2, winner=None),
        ],
    )
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(partial, sm, tmp_path)

    await consumer.handle_event(sha, user_id=1)
    parser_session.expire_all()

    row = (await parser_session.execute(select(Match))).scalar_one()
    assert row.review_status == "pending_review"
    assert row.review_reason is not None
    assert "No game winners resolved" in row.review_reason
    assert "2 games observed" in row.review_reason


@pytest.mark.asyncio
async def test_consumer_no_review_reason_on_conclusive(parser_session: Any, tmp_path: Path) -> None:
    sha = "c" * 64
    _write_raw(tmp_path, sha)
    conclusive = ParsedMatch(
        raw_match_id="reason-uuid-2",
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
    assert row.review_reason is None


# ---------------------------------------------------------------------------
# Persistence-level: review_reason cleared on conclusive reparse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_review_reason_cleared_on_conclusive_reparse(parser_session: Any) -> None:
    raw_id = "reason-logical-1"
    sha_partial = "e1" + "0" * 62
    sha_conclusive = "e2" + "0" * 62

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
        review_reason="No game winners resolved (1 game observed)",
    )

    parser_session.expire_all()
    after_partial = (await parser_session.execute(select(Match))).scalar_one()
    assert after_partial.review_status == "pending_review"
    assert after_partial.review_reason == "No game winners resolved (1 game observed)"

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
        review_reason=None,
    )

    parser_session.expire_all()
    after_conclusive = (await parser_session.execute(select(Match))).scalar_one()
    assert after_conclusive.review_status is None
    assert after_conclusive.review_reason is None


# ---------------------------------------------------------------------------
# Persistence-level: rejected row preserves review_reason
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rejected_row_preserves_review_reason(parser_session: Any) -> None:
    raw_id = "reason-logical-2"
    sha_a = "f1" + "0" * 62
    sha_b = "f2" + "0" * 62

    rejected = Match(
        id=uuid.uuid4(),
        sha256=sha_a,
        user_id=1,
        raw_match_id=raw_id,
        players=["alice", "bob"],
        winner=None,
        game_count=1,
        review_status="rejected",
        review_reason="No game winners resolved (1 game observed)",
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
        review_reason=None,
    )

    parser_session.expire_all()
    survivor = (await parser_session.execute(select(Match))).scalar_one()
    assert survivor.review_status == "rejected"
    # The reason from the original rejected row is preserved (the update
    # path skips setting review_reason on rejected rows).
    assert survivor.review_reason == "No game winners resolved (1 game observed)"


@pytest.fixture(autouse=True)
def _ensure_loop_policy() -> None:
    asyncio.get_event_loop_policy()
