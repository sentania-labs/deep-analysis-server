"""Test that archetype classification commit failure rolls back the session.

When ``session.commit()`` fails after writing MatchArchetype rows, the
consumer must call ``session.rollback()`` so the session is not left in
a dirty/poisoned state.  Without the rollback, the subsequent
``_materialize_card_game_stats`` call inherits the broken transaction
and cascades the failure.

This is a unit test — no database needed.  The session is fully mocked
to verify the rollback→materialize sequence.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from parser_service.consumer import ParserConsumer
from parser_service.parsing.models import GameEvent, ParsedGame, ParsedMatch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubParser:
    """Return a canned ParsedMatch from .parse()."""

    def __init__(self, parsed: ParsedMatch) -> None:
        self._parsed = parsed

    def parse(self, content: bytes) -> ParsedMatch:
        return self._parsed


class _NoopPublisher:
    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        return None


def _write_raw(raw_root: Path, sha: str) -> None:
    shard = raw_root / sha[0:2] / sha[2:4]
    shard.mkdir(parents=True, exist_ok=True)
    (shard / f"{sha}.dat").write_bytes(b"stub-content")


def _make_parsed() -> ParsedMatch:
    """A minimal conclusive parse with game events (needed for
    card_game_stats materialization to have something to work with)."""
    return ParsedMatch(
        raw_match_id="rollback-test-uuid",
        players=["hero", "villain"],
        winner="hero",
        match_result="2-0",
        games=[
            ParsedGame(
                game_number=1,
                winner="hero",
                events=[
                    GameEvent(
                        turn_number=1,
                        verb="cast",
                        card_name="Lightning Bolt",
                        player="hero",
                    ),
                ],
            ),
            ParsedGame(
                game_number=2,
                winner="hero",
                events=[
                    GameEvent(
                        turn_number=1,
                        verb="cast",
                        card_name="Counterspell",
                        player="villain",
                    ),
                ],
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_archetype_commit_failure_triggers_rollback(tmp_path: Path) -> None:
    """When session.commit() fails during archetype classification, the
    consumer must rollback before proceeding to card_game_stats."""

    sha = "ab" * 32
    _write_raw(tmp_path, sha)
    parsed = _make_parsed()

    # -- Build a mock session that tracks commit/rollback calls.
    match_id = uuid.uuid4()

    mock_match = MagicMock()
    mock_match.id = match_id
    mock_match.format = "legacy"
    mock_match.format_source = "inferred"
    mock_match.archetype_id = None

    mock_session = AsyncMock()

    # commit() should fail on the first call (archetype block) but
    # succeed on subsequent calls (card_game_stats and later).
    commit_call_count = 0

    async def _commit_side_effect() -> None:
        nonlocal commit_call_count
        commit_call_count += 1
        if commit_call_count == 1:
            raise RuntimeError("simulated commit failure in archetype block")

    mock_session.commit = AsyncMock(side_effect=_commit_side_effect)
    mock_session.rollback = AsyncMock()
    mock_session.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: None))

    # Session context manager
    class _SessionCtx:
        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, *exc):
            return False

    class _SessionMaker:
        def __call__(self):
            return _SessionCtx()

    # -- Build the consumer with patched dependencies.
    consumer = ParserConsumer(
        redis_client=MagicMock(),
        sessionmaker=_SessionMaker(),
        raw_root=tmp_path,
        parser=_StubParser(parsed),
        publisher=_NoopPublisher(),
    )

    # Stub _resolve_hero so it doesn't hit auth DB.
    async def _stub_resolve_hero(_uid: int, players: list[str]) -> str | None:
        return str(players[0]) if players else None

    consumer._resolve_hero = _stub_resolve_hero  # type: ignore[assignment]

    # Patch persist_match to return our mock match, and patch the
    # analytics settings to enable archetype classification.
    with (
        patch(
            "parser_service.consumer.persist_match",
            new_callable=AsyncMock,
            return_value=mock_match,
        ),
        patch(
            "parser_service.consumer.get_parser_settings",
            return_value=MagicMock(analytics_service_url="http://analytics:8000"),
        ),
        patch(
            "parser_service.consumer.analytics_client.classify_with_confidence",
            new_callable=AsyncMock,
            return_value=MagicMock(
                archetype_id=uuid.uuid4(),
                confidence=0.9,
            ),
        ),
        patch(
            "parser_service.consumer._materialize_card_game_stats",
            new_callable=AsyncMock,
        ) as mock_materialize,
        patch(
            "parser_service.consumer.link_deck_to_match",
            new_callable=AsyncMock,
        ),
    ):
        result = await consumer.handle_event(sha, user_id=1)

    # The parse should succeed overall (not abort).
    assert result is not None

    # The archetype commit failed, so rollback MUST have been called
    # before _materialize_card_game_stats runs.
    mock_session.rollback.assert_awaited_once()

    # card_game_stats materialization must still have been attempted
    # (the session was recovered via rollback).
    mock_materialize.assert_awaited_once()
