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
    _coerce_agent_classification,
)
from parser_service.models import Match
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.persistence import persist_match
from sqlalchemy import select

from common.storage import MemoryObjectStore, object_key

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


def _store_with(sha: str, body: bytes = b"unused-by-stub-parser") -> MemoryObjectStore:
    """A raw archive holding one object at the key ingest would use."""
    store = MemoryObjectStore()
    store.seed(object_key(sha), body)
    return store


def _consumer_with(parsed: ParsedMatch, sm: Any, store: MemoryObjectStore) -> ParserConsumer:
    class _DummyRedis:
        def pubsub(self) -> Any:
            raise NotImplementedError

    consumer = ParserConsumer(
        redis_client=_DummyRedis(),
        sessionmaker=sm,
        store=store,
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
    store = _store_with(sha)
    partial = ParsedMatch(
        raw_match_id="reason-uuid-1",
        players=["alice", "bob"],
        games=[
            ParsedGame(game_number=1, winner=None),
            ParsedGame(game_number=2, winner=None),
        ],
    )
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(partial, sm, store)

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
    store = _store_with(sha)
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
    consumer = _consumer_with(conclusive, sm, store)

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


# ---------------------------------------------------------------------------
# Agent tail-scan verdict (issue #125)
#
# The agent ships an ``agent_classification`` of "complete" or
# "inconclusive" with each match log. It rides file.ingested through to
# the review reason so an admin can tell "the agent's tail scan saw no
# completion signal" apart from "the parser could not resolve winners".
# ---------------------------------------------------------------------------


class TestAgentClassificationInReviewReason:
    @staticmethod
    def _partial() -> ParsedMatch:
        return ParsedMatch(
            players=["alice", "bob"],
            games=[
                ParsedGame(game_number=1, winner=None),
                ParsedGame(game_number=2, winner=None),
            ],
        )

    def test_omitted_verdict_matches_legacy_wording(self) -> None:
        """No verdict (old agent) leaves the string exactly as before."""
        parsed = self._partial()
        assert _build_review_reason(parsed) == _build_review_reason(parsed, None)
        assert "agent tail scan" not in _build_review_reason(parsed)

    def test_inconclusive_verdict_is_named(self) -> None:
        reason = _build_review_reason(self._partial(), "inconclusive")
        assert "No game winners resolved" in reason
        assert "agent tail scan: inconclusive" in reason

    def test_complete_verdict_is_distinguishable(self) -> None:
        """A 'complete' file the parser could not resolve reads differently."""
        inconclusive = _build_review_reason(self._partial(), "inconclusive")
        complete = _build_review_reason(self._partial(), "complete")
        assert "agent tail scan: complete" in complete
        assert complete != inconclusive

    def test_unknown_verdict_is_ignored(self) -> None:
        """A junk value degrades to the parser-only reason, never raises."""
        parsed = self._partial()
        assert _build_review_reason(parsed, "banana") == _build_review_reason(parsed)


class TestCoerceAgentClassification:
    def test_accepts_contracted_values(self) -> None:
        assert _coerce_agent_classification("complete") == "complete"
        assert _coerce_agent_classification("inconclusive") == "inconclusive"

    def test_rejects_everything_else(self) -> None:
        for raw in (None, "", "COMPLETE", "partial", 3, True):
            assert _coerce_agent_classification(raw) is None


@pytest.mark.asyncio
async def test_consumer_records_agent_verdict_on_partial(
    parser_session: Any, tmp_path: Path
) -> None:
    sha = "a1" + "0" * 62
    store = _store_with(sha)
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(
        ParsedMatch(
            raw_match_id="agent-verdict-uuid-1",
            players=["alice", "bob"],
            games=[ParsedGame(game_number=1, winner=None)],
        ),
        sm,
        store,
    )

    await consumer.handle_event(sha, user_id=1, agent_classification="inconclusive")
    parser_session.expire_all()

    row = (await parser_session.execute(select(Match))).scalar_one()
    assert row.review_status == "pending_review"
    assert row.review_reason is not None
    # Both signals present and separable in the one string an admin sees.
    assert "No game winners resolved" in row.review_reason
    assert "agent tail scan: inconclusive" in row.review_reason


@pytest.mark.asyncio
async def test_consumer_partial_without_agent_verdict_unchanged(
    parser_session: Any, tmp_path: Path
) -> None:
    """A parser-derived hold with no agent verdict says nothing about one."""
    sha = "a2" + "0" * 62
    store = _store_with(sha)
    sm = _session_maker_returning(parser_session)
    consumer = _consumer_with(
        ParsedMatch(
            raw_match_id="agent-verdict-uuid-2",
            players=["alice", "bob"],
            games=[ParsedGame(game_number=1, winner=None)],
        ),
        sm,
        store,
    )

    await consumer.handle_event(sha, user_id=1)
    parser_session.expire_all()

    row = (await parser_session.execute(select(Match))).scalar_one()
    assert row.review_status == "pending_review"
    assert row.review_reason is not None
    assert "agent tail scan" not in row.review_reason


@pytest.mark.asyncio
async def test_handle_routes_agent_classification_from_event(tmp_path: Path) -> None:
    """The file.ingested decode path forwards the verdict to handle_event."""
    import json as _json

    store = _store_with("f" * 64)
    sm = _session_maker_returning(None)
    consumer = _consumer_with(ParsedMatch(games=[]), sm, store)

    seen: list[tuple[str, int, str | None]] = []

    async def _capture(sha256: str, user_id: int, agent_classification: str | None = None) -> None:
        seen.append((sha256, user_id, agent_classification))

    consumer.handle_event = _capture

    base = {"sha256": "f" * 64, "user_id": 7, "content_type": "match-log"}
    await consumer._handle({"data": _json.dumps({**base, "agent_classification": "inconclusive"})})
    await consumer._handle({"data": _json.dumps(base)})
    await consumer._handle({"data": _json.dumps({**base, "agent_classification": "nonsense"})})

    assert seen == [
        ("f" * 64, 7, "inconclusive"),
        ("f" * 64, 7, None),
        ("f" * 64, 7, None),
    ]
