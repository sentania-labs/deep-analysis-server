"""Tests for the consumer's partial-parse skip gate (#71).

The agent's 5-second stability gate fires during natural lulls in
play, so MTGO's growing ``Match_GameLog_*.dat`` is shipped to the
server multiple times during a single match. ``_is_partial_parse``
keeps these in-progress snapshots out of persistence — a later
snapshot of the same logical match (same ``raw_match_id``) carries
the resolved winners and gets stored instead.

A real Magic *draw* must NOT be treated as partial: every game has a
winner field but neither player wins the majority, so the match-level
winner is None while ``parsed.games[*].winner`` is populated.
"""

from __future__ import annotations

from parser_service.consumer import _is_partial_parse
from parser_service.parsing.models import ParsedGame, ParsedMatch


def test_completely_empty_parse_is_partial() -> None:
    parsed = ParsedMatch()
    assert _is_partial_parse(parsed) is True


def test_game_header_without_winner_is_partial() -> None:
    """MTGO emitted a 'Game 1 of N' header but the game has not finished
    yet. The agent shipped the snapshot during a lull — skip it so the
    match doesn't show up in the dashboard as a Draw husk."""
    parsed = ParsedMatch(
        players=["alice", "bob"],
        games=[ParsedGame(game_number=1, winner=None)],
    )
    assert _is_partial_parse(parsed) is True


def test_match_with_winner_is_not_partial() -> None:
    """A normal completed match — match-level winner is set."""
    parsed = ParsedMatch(
        players=["alice", "bob"],
        winner="alice",
        match_result="2-0",
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="alice"),
        ],
    )
    assert _is_partial_parse(parsed) is False


def test_real_draw_is_not_partial() -> None:
    """Each game has a winner but the match itself does not — that's
    a true Magic draw (e.g. 1-1 with a third game drawn). The gate
    must let this through so it lands in the DB as a real draw."""
    parsed = ParsedMatch(
        players=["alice", "bob"],
        winner=None,
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner="bob"),
            ParsedGame(game_number=3, winner=None, result="draw"),
        ],
    )
    # match.winner is None but at least one game has a winner → not partial
    assert _is_partial_parse(parsed) is False


def test_match_with_only_one_game_finished_is_not_partial() -> None:
    """A multi-game match still in progress, but at least one game has
    completed — better to persist a partially-played match than drop it.
    The 'better parse' upsert in persist_match will let a later, more
    complete snapshot overwrite this one."""
    parsed = ParsedMatch(
        players=["alice", "bob"],
        winner=None,
        games=[
            ParsedGame(game_number=1, winner="alice"),
            ParsedGame(game_number=2, winner=None),
        ],
    )
    assert _is_partial_parse(parsed) is False
