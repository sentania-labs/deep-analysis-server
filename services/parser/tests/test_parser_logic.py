"""Unit tests for the MTGO log parser."""

from __future__ import annotations

from pathlib import Path

import pytest
from parser_service.parsing import (
    LogParser,
    MTGODatStrategy,
    MTGOTextLogStrategy,
    ParsedMatch,
)
from parser_service.parsing.parser import _parse_mana_string

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# --- text-log strategy detection ------------------------------------------


def test_text_strategy_recognises_mtgo_log() -> None:
    strategy = MTGOTextLogStrategy()
    assert strategy.can_parse(_read("match_2_0_modern.log"))


def test_text_strategy_rejects_garbage() -> None:
    strategy = MTGOTextLogStrategy()
    assert not strategy.can_parse(_read("non_log_garbage.bin"))


def test_text_strategy_rejects_empty() -> None:
    assert not MTGOTextLogStrategy().can_parse(b"")


def test_dat_strategy_is_disabled_until_implemented() -> None:
    strategy = MTGODatStrategy()
    # No payload should be claimed yet — placeholder slot.
    assert not strategy.can_parse(b"\x00\x01\x02\x03")
    with pytest.raises(NotImplementedError):
        strategy.parse(b"\x00\x01\x02\x03")


# --- end-to-end parse -----------------------------------------------------


def test_parse_full_match_extracts_metadata() -> None:
    parser = LogParser()
    parsed = parser.parse(_read("match_2_0_modern.log"))

    assert parsed.format == "modern"
    assert parsed.event_type == "league"
    assert parsed.raw_match_id == "M-12345"
    assert parsed.players == ["Alice", "Bob"]
    assert parsed.winner == "Alice"
    assert parsed.match_result == "2-0"
    assert parsed.game_count == 2


def test_parse_full_match_per_game_winners() -> None:
    parsed = LogParser().parse(_read("match_2_0_modern.log"))
    g1, g2 = parsed.games
    assert g1.game_number == 1
    assert g1.winner == "Alice"
    assert g1.result == "win"
    assert g2.game_number == 2
    assert g2.winner == "Alice"


def test_parse_full_match_extracts_turns_and_state() -> None:
    parsed = LogParser().parse(_read("match_2_0_modern.log"))
    g1 = parsed.games[0]

    assert len(g1.turns) >= 4
    t1 = g1.turns[0]
    assert t1.turn_number == 1
    assert t1.active_player == "Alice"
    assert "Alice" in t1.players
    assert "Bob" in t1.players
    # Bolt resolved this turn, Bob's life should be 17 by end of window.
    assert t1.players["Bob"].life == 17

    # Mountain played by Alice should appear on her battlefield.
    assert "Mountain" in t1.players["Alice"].zones.battlefield


def test_parse_full_match_captures_mana_pool() -> None:
    parsed = LogParser().parse(_read("match_2_0_modern.log"))
    g1 = parsed.games[0]
    t3 = next(t for t in g1.turns if t.turn_number == 3)
    assert t3.players["Alice"].mana_pool.R == 1


def test_parse_full_match_captures_stack() -> None:
    parsed = LogParser().parse(_read("match_2_0_modern.log"))
    g1 = parsed.games[0]
    t3 = next(t for t in g1.turns if t.turn_number == 3)
    assert any("Goblin Guide" in entry.description for entry in t3.stack)


def test_parse_minimal_log_yields_partial_match() -> None:
    """No winner declared — we still surface format/players/turns."""
    parsed = LogParser().parse(_read("match_minimal_no_winner.log"))
    assert parsed.format == "pauper"
    assert parsed.players == ["Alice", "Bob"]
    assert parsed.winner is None
    assert parsed.match_result is None
    assert parsed.game_count == 1
    assert parsed.games[0].winner is None


def test_parse_garbage_returns_empty_match() -> None:
    parsed = LogParser().parse(_read("non_log_garbage.bin"))
    assert isinstance(parsed, ParsedMatch)
    assert parsed.winner is None
    assert parsed.games == []
    assert parsed.format is None


def test_parse_empty_returns_empty_match() -> None:
    parsed = LogParser().parse(b"")
    assert parsed.winner is None
    assert parsed.games == []


# --- mana parsing ---------------------------------------------------------


def test_parse_mana_string_pure_colors() -> None:
    pool = _parse_mana_string("WUBRG")
    assert pool.W == 1
    assert pool.U == 1
    assert pool.B == 1
    assert pool.R == 1
    assert pool.G == 1
    assert pool.C == 0


def test_parse_mana_string_with_generic() -> None:
    pool = _parse_mana_string("R2")
    assert pool.R == 1
    assert pool.C == 2


def test_parse_mana_string_double_color() -> None:
    pool = _parse_mana_string("RR")
    assert pool.R == 2


# --- strategy ordering ----------------------------------------------------


def test_strategy_order_text_wins_when_dat_disabled() -> None:
    parser = LogParser()
    parsed = parser.parse(_read("match_2_0_modern.log"))
    # If MTGODatStrategy ever claimed the payload, the text-derived
    # winner would not surface. Keep this guard until .dat is real.
    assert parsed.winner == "Alice"


def test_custom_strategy_list_is_honoured() -> None:
    """Caller can swap strategies — used by tests / future formats."""
    parser = LogParser(strategies=[MTGOTextLogStrategy()])
    parsed = parser.parse(_read("match_2_0_modern.log"))
    assert parsed.winner == "Alice"
