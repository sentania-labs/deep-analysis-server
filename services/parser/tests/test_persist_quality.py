"""Tests for the "better parse" ordering used by persist_match (#71).

MTGO appends to ``Match_GameLog_<uuid>.dat`` throughout a match, so
the agent ships multiple snapshots of the same logical match. With
``raw_match_id``-keyed identity in place, ``persist_match`` must
decide whether a new snapshot should overwrite the stored row — and
that decision is driven by :func:`_parse_quality_key`.
"""

from __future__ import annotations

from parser_service.persistence import _parse_quality_key


class TestParseQualityKey:
    """The ordering: winner-presence beats game-count beats nothing."""

    def test_winner_beats_no_winner_regardless_of_games(self) -> None:
        """A parse with a winner is always strictly better than one without,
        even if the winnerless parse has more games captured."""
        with_winner = _parse_quality_key("alice", 2)
        no_winner_more_games = _parse_quality_key(None, 5)
        assert with_winner > no_winner_more_games

    def test_more_games_wins_when_winner_status_equal(self) -> None:
        """Among parses with the same winner-status, more games wins."""
        assert _parse_quality_key("alice", 3) > _parse_quality_key("alice", 2)
        assert _parse_quality_key(None, 2) > _parse_quality_key(None, 1)

    def test_tie_does_not_imply_new_wins(self) -> None:
        """Equal quality returns equal keys — the upsert path will then
        decide whether to overwrite based on the tie-break (new wins)."""
        assert _parse_quality_key("alice", 3) == _parse_quality_key("bob", 3)

    def test_zero_games_no_winner_is_lowest(self) -> None:
        """An empty parse is the lowest-quality result possible."""
        empty = _parse_quality_key(None, 0)
        assert empty < _parse_quality_key(None, 1)
        assert empty < _parse_quality_key("alice", 0)
