"""Unit tests for the MTGO log parser."""

from __future__ import annotations

from pathlib import Path

from parser_service.parsing import (
    LogParser,
    MTGODatStrategy,
    MTGOTextLogStrategy,
    ParsedMatch,
)
from parser_service.parsing.parser import _parse_mana_string

FIXTURES = Path(__file__).parent / "fixtures"

# Real MTGO ``.dat`` game-log fixtures captured from live play. The
# expected per-fixture values below are the ground truth for the binary
# parser and double as a regression suite if the framing format shifts.
DAT_FIXTURE_01EA1246 = "Match_GameLog_01ea1246-6306-483b-b03d-d0f7bf203e28.dat"
DAT_FIXTURE_2B464924 = "Match_GameLog_2b464924-54fb-4b05-8e3f-d4cfbd9a0310.dat"
DAT_FIXTURE_40087184 = "Match_GameLog_40087184-b709-4109-8ee8-7112e894b834.dat"
DAT_FIXTURE_4873FBEE = "Match_GameLog_4873fbee-48a8-4830-8864-d5631db75f0b.dat"


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


def test_dat_strategy_recognises_real_dat_fixture() -> None:
    strategy = MTGODatStrategy()
    assert strategy.can_parse(_read(DAT_FIXTURE_01EA1246))


def test_dat_strategy_rejects_garbage() -> None:
    strategy = MTGODatStrategy()
    assert not strategy.can_parse(b"\x00\x01\x02\x03")
    assert not strategy.can_parse(b"")


def test_dat_strategy_does_not_claim_text_log() -> None:
    """Plaintext logs lack the .dat hints — text strategy should win."""
    assert not MTGODatStrategy().can_parse(_read("match_2_0_modern.log"))


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


def test_strategy_order_text_handles_synthetic_log() -> None:
    """Plaintext fixture is claimed by the text strategy, not the .dat one."""
    parser = LogParser()
    parsed = parser.parse(_read("match_2_0_modern.log"))
    assert parsed.winner == "Alice"


def test_custom_strategy_list_is_honoured() -> None:
    """Caller can swap strategies — used by tests / future formats."""
    parser = LogParser(strategies=[MTGOTextLogStrategy()])
    parsed = parser.parse(_read("match_2_0_modern.log"))
    assert parsed.winner == "Alice"


# --- real .dat parsing ----------------------------------------------------


def test_dat_extracts_match_id_and_players() -> None:
    parsed = LogParser().parse(_read(DAT_FIXTURE_01EA1246))
    assert parsed.raw_match_id == "01ea1246-6306-483b-b03d-d0f7bf203e28"
    assert sorted(parsed.players) == ["WANGSU", "sentania"]


def test_dat_2_1_match_winner_and_three_games() -> None:
    parsed = LogParser().parse(_read(DAT_FIXTURE_01EA1246))
    assert parsed.winner == "sentania"
    assert parsed.match_result == "2-1"
    assert parsed.game_count == 3
    g1, g2, g3 = parsed.games
    # MTGO emits both ``X has conceded`` and ``OPP wins the game`` for
    # a concession, so the winner is the opponent and result == "win".
    assert (g1.winner, g1.result) == ("sentania", "win")
    assert (g2.winner, g2.result) == ("WANGSU", "win")
    assert (g3.winner, g3.result) == ("sentania", "win")


def test_dat_2_0_loss_winner_and_two_games() -> None:
    parsed = LogParser().parse(_read(DAT_FIXTURE_4873FBEE))
    assert parsed.winner == "DiamondCommando"
    assert parsed.match_result == "2-0"
    assert parsed.game_count == 2
    assert all(g.winner == "DiamondCommando" for g in parsed.games)


def test_dat_2_0_win_winner_and_two_games() -> None:
    parsed = LogParser().parse(_read(DAT_FIXTURE_40087184))
    assert parsed.winner == "sentania"
    assert parsed.match_result == "2-0"
    assert parsed.game_count == 2
    assert all(g.winner == "sentania" for g in parsed.games)


def test_dat_match_with_numeric_username() -> None:
    """Player ``214`` exercises the numeric-leading-character path."""
    parsed = LogParser().parse(_read(DAT_FIXTURE_2B464924))
    assert parsed.winner == "214"
    assert parsed.match_result == "2-1"
    assert parsed.game_count == 3
    assert "214" in parsed.players
    assert "sentania" in parsed.players


def test_dat_card_names_are_clean() -> None:
    """Card refs ``@[Name@:cat,inst:@]`` should yield bare card names."""
    parsed = LogParser().parse(_read(DAT_FIXTURE_01EA1246))
    cards: set[str] = set()
    for game in parsed.games:
        for turn in game.turns:
            for snap in turn.players.values():
                cards.update(snap.zones.battlefield)
    assert "Force of Will" in cards
    assert "Tamiyo, Inquisitive Student" in cards
    assert "Tropical Island" in cards
    # No catalog-id artifacts should leak through.
    assert not any("@" in c or ":" in c for c in cards)


def test_dat_turns_use_canonical_player_names() -> None:
    """Trailing binary-header bytes must not corrupt active-player capture."""
    parsed = LogParser().parse(_read(DAT_FIXTURE_01EA1246))
    assert parsed.games, "expected at least one game"
    canonical = set(parsed.players)
    for game in parsed.games:
        for turn in game.turns:
            assert turn.active_player in canonical
            assert set(turn.players).issubset(canonical)


def test_dat_strategy_claims_dat_before_text_strategy() -> None:
    """Default LogParser order routes .dat payloads to the binary strategy."""
    parser = LogParser()
    parsed = parser.parse(_read(DAT_FIXTURE_40087184))
    # MTGOTextLogStrategy doesn't know about ``@P``-framed lines, so
    # if it claimed the payload the winner / score would be wrong.
    assert parsed.raw_match_id == "40087184-b709-4109-8ee8-7112e894b834"
    assert parsed.match_result == "2-0"


def test_dat_unrecognised_payload_returns_empty_match() -> None:
    parsed = LogParser().parse(b"\x00\x01\x02\x03not a real log")
    assert isinstance(parsed, ParsedMatch)
    assert parsed.winner is None
    assert parsed.games == []
