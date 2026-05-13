"""Tests for v0.9.0 game state reconstruction — play/draw, mulligans,
draw/zone tracking, and life payment extraction from .dat fixtures.

Life tracking caveat: only explicit "paying N life" is tracked.
Combat damage is NOT logged in the .dat format and is not tracked.
Assertions use <= / >= bounds, not exact values, because the parser
is best-effort for life totals.
"""

from __future__ import annotations

from pathlib import Path

from parser_service.parsing import LogParser

FIXTURES = Path(__file__).parent / "fixtures"

# Fixture shorthand — same as test_parser_logic.py.
DAT_01EA1246 = "Match_GameLog_01ea1246-6306-483b-b03d-d0f7bf203e28.dat"
DAT_2B464924 = "Match_GameLog_2b464924-54fb-4b05-8e3f-d4cfbd9a0310.dat"
DAT_40087184 = "Match_GameLog_40087184-b709-4109-8ee8-7112e894b834.dat"
DAT_4873FBEE = "Match_GameLog_4873fbee-48a8-4830-8864-d5631db75f0b.dat"


def _parse(name: str):
    return LogParser().parse((FIXTURES / name).read_bytes())


# ── play/draw detection ─────────────────────────────────────────────────


class TestPlayDraw:
    """Verify play_first and on_play across all .dat fixtures."""

    def test_01ea1246_game1_wangsu_plays_first(self) -> None:
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        assert g1.play_first == "WANGSU"
        # WANGSU is players[0], so on_play is True
        assert g1.on_play is True

    def test_01ea1246_game3_sentania_plays_first(self) -> None:
        parsed = _parse(DAT_01EA1246)
        g3 = parsed.games[2]
        assert g3.play_first == "sentania"
        # sentania is players[1], so on_play is False
        assert g3.on_play is False

    def test_2b464924_game1_sentania_plays_first(self) -> None:
        parsed = _parse(DAT_2B464924)
        g1 = parsed.games[0]
        assert g1.play_first == "sentania"

    def test_2b464924_game3_214_plays_first(self) -> None:
        parsed = _parse(DAT_2B464924)
        g3 = parsed.games[2]
        assert g3.play_first == "214"
        assert g3.on_play is True  # 214 is players[0]

    def test_40087184_game1_sentania_plays_first(self) -> None:
        parsed = _parse(DAT_40087184)
        g1 = parsed.games[0]
        assert g1.play_first == "sentania"

    def test_40087184_game2_youngjustin_plays_first(self) -> None:
        parsed = _parse(DAT_40087184)
        g2 = parsed.games[1]
        assert g2.play_first == "YoungJustin"
        assert g2.on_play is True  # YoungJustin is players[0]

    def test_4873fbee_game1_diamondcommando_plays_first(self) -> None:
        parsed = _parse(DAT_4873FBEE)
        g1 = parsed.games[0]
        assert g1.play_first == "DiamondCommando"

    def test_4873fbee_game2_sentania_plays_first(self) -> None:
        parsed = _parse(DAT_4873FBEE)
        g2 = parsed.games[1]
        assert g2.play_first == "sentania"

    def test_every_game_has_play_first(self) -> None:
        """All games across all fixtures should detect play/draw."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                assert g.play_first is not None, f"{name} game {g.game_number}: play_first is None"
                assert g.on_play is not None, f"{name} game {g.game_number}: on_play is None"


# ── mulligan / opening hand size detection ──────────────────────────────


class TestOpeningHandSizes:
    """Verify opening_hand_sizes extraction."""

    def test_01ea1246_game1_both_keep_seven(self) -> None:
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        assert g1.opening_hand_sizes == {"WANGSU": 7, "sentania": 7}

    def test_01ea1246_game3_wangsu_mulligans_to_six(self) -> None:
        parsed = _parse(DAT_01EA1246)
        g3 = parsed.games[2]
        assert g3.opening_hand_sizes["WANGSU"] == 6
        assert g3.opening_hand_sizes["sentania"] == 7

    def test_40087184_game1_sentania_mulligans_to_five(self) -> None:
        """sentania mulligans twice (7 → 6 → 5) in game 1."""
        parsed = _parse(DAT_40087184)
        g1 = parsed.games[0]
        assert g1.opening_hand_sizes["sentania"] == 5
        assert g1.opening_hand_sizes["YoungJustin"] == 7

    def test_40087184_game2_both_keep_seven(self) -> None:
        parsed = _parse(DAT_40087184)
        g2 = parsed.games[1]
        assert g2.opening_hand_sizes == {"YoungJustin": 7, "sentania": 7}

    def test_4873fbee_game1_diamondcommando_mulligans_to_four(self) -> None:
        """DiamondCommando mulligans three times (7 → 6 → 5 → 4)."""
        parsed = _parse(DAT_4873FBEE)
        g1 = parsed.games[0]
        assert g1.opening_hand_sizes["DiamondCommando"] == 4
        assert g1.opening_hand_sizes["sentania"] == 7

    def test_4873fbee_game2_diamondcommando_mulligans_to_four_again(self) -> None:
        parsed = _parse(DAT_4873FBEE)
        g2 = parsed.games[1]
        assert g2.opening_hand_sizes["DiamondCommando"] == 4

    def test_2b464924_game1_214_mulligans_to_six(self) -> None:
        parsed = _parse(DAT_2B464924)
        g1 = parsed.games[0]
        assert g1.opening_hand_sizes["214"] == 6
        assert g1.opening_hand_sizes["sentania"] == 7

    def test_every_game_has_hand_sizes(self) -> None:
        """All games should have at least one player's hand size."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                assert g.opening_hand_sizes, (
                    f"{name} game {g.game_number}: opening_hand_sizes is empty"
                )


# ── draw tracking ───────────────────────────────────────────────────────


class TestDrawTracking:
    """Verify that card draws populate the hand zone."""

    def test_hand_zone_grows_with_draws(self) -> None:
        """After multiple turns, hand zone should have entries from draws."""
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        assert g1.turns, "expected turns"
        last_turn = g1.turns[-1]
        # Both players should have drawn cards by the last turn.
        for player in ("WANGSU", "sentania"):
            hand = last_turn.players[player].zones.hand
            assert len(hand) > 0, f"{player} hand zone is empty at end of game"

    def test_anonymous_draws_tracked_as_unknown(self) -> None:
        """'draws a card.' lines should add 'unknown' to hand."""
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        # After a few turns, at least one "unknown" should appear.
        all_hand_cards: list[str] = []
        for turn in g1.turns:
            for snap in turn.players.values():
                all_hand_cards.extend(snap.zones.hand)
        assert "unknown" in all_hand_cards

    def test_multi_draw_adds_multiple_entries(self) -> None:
        """'draws three cards with Brainstorm' → 3 entries in hand."""
        parsed = _parse(DAT_01EA1246)
        # Game 1 has Brainstorm draws. Check that a turn with Brainstorm
        # adds 3 hand entries in a single turn window.
        g1 = parsed.games[0]
        prev_hand_count: dict[str, int] = {}
        brainstorm_turn_found = False
        for turn in g1.turns:
            for name, snap in turn.players.items():
                cur = len(snap.zones.hand)
                prev = prev_hand_count.get(name, 0)
                # A turn with Brainstorm should add at least 3 to hand.
                if cur - prev >= 3:
                    brainstorm_turn_found = True
                prev_hand_count[name] = cur
        assert brainstorm_turn_found, "expected a turn with 3+ new hand entries (Brainstorm)"


# ── graveyard tracking ──────────────────────────────────────────────────


class TestGraveyardTracking:
    """Verify 'puts ... into their graveyard' populates graveyard zone."""

    def test_01ea1246_flusterstorm_in_graveyard(self) -> None:
        """WANGSU puts Flusterstorm into their graveyard in game 1."""
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        last_turn = g1.turns[-1]
        gy = last_turn.players["WANGSU"].zones.graveyard
        assert "Flusterstorm" in gy

    def test_40087184_thoughtseize_in_graveyard(self) -> None:
        """YoungJustin puts Thoughtseize into their graveyard in game 1."""
        parsed = _parse(DAT_40087184)
        g1 = parsed.games[0]
        last_turn = g1.turns[-1]
        gy = last_turn.players["YoungJustin"].zones.graveyard
        assert "Thoughtseize" in gy

    def test_graveyard_cards_are_clean(self) -> None:
        """Graveyard entries should be clean card names, no @-artifacts."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                for turn in g.turns:
                    for snap in turn.players.values():
                        for card in snap.zones.graveyard:
                            assert "@" not in card, f"dirty graveyard entry: {card}"


# ── exile tracking ──────────────────────────────────────────────────────


class TestExileTracking:
    """Verify 'exiles ...' populates exile zone."""

    def test_01ea1246_atraxa_exiled_by_force(self) -> None:
        """sentania exiles Atraxa, Grand Unifier with Force of Will's ability."""
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        last_turn = g1.turns[-1]
        exile = last_turn.players["sentania"].zones.exile
        assert "Atraxa, Grand Unifier" in exile

    def test_4873fbee_exile_zone_populated(self) -> None:
        """DiamondCommando exiles cards across games 1 and 2."""
        parsed = _parse(DAT_4873FBEE)
        for g in parsed.games:
            last_turn = g.turns[-1]
            all_exile = sum(len(snap.zones.exile) for snap in last_turn.players.values())
            assert all_exile > 0, f"game {g.game_number}: no cards exiled"

    def test_exile_cards_are_clean(self) -> None:
        """Exile entries should be clean card names."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                for turn in g.turns:
                    for snap in turn.players.values():
                        for card in snap.zones.exile:
                            assert "@" not in card, f"dirty exile entry: {card}"


# ── life payment tracking ───────────────────────────────────────────────


class TestLifePaymentTracking:
    """Verify best-effort life tracking from 'paying N life' patterns.

    Only life PAYMENTS (Force of Will, Snuff Out, fetch lands, etc.) are
    tracked. Combat damage is NOT logged in the .dat format.
    """

    def test_force_of_will_costs_1_life(self) -> None:
        """Games with Force of Will casts should show life < 20."""
        parsed = _parse(DAT_01EA1246)
        g1 = parsed.games[0]
        last_turn = g1.turns[-1]
        # WANGSU casts FoW paying 1 life at least twice in game 1
        assert last_turn.players["WANGSU"].life < 20

    def test_snuff_out_costs_4_life(self) -> None:
        """YoungJustin casts Snuff Out paying 4 life in game 1 of 40087184."""
        parsed = _parse(DAT_40087184)
        g1 = parsed.games[0]
        last_turn = g1.turns[-1]
        assert last_turn.players["YoungJustin"].life <= 16

    def test_life_decrements_are_cumulative(self) -> None:
        """Multiple FoW casts by the same player accumulate life loss."""
        parsed = _parse(DAT_01EA1246)
        # Game 2: WANGSU casts FoW paying 1 life multiple times
        g2 = parsed.games[1]
        last_turn = g2.turns[-1]
        # At least 2 FoW casts → life should be <= 18
        assert last_turn.players["WANGSU"].life <= 18

    def test_all_fixtures_have_life_payments(self) -> None:
        """Every fixture has at least one FoW, so some player should be < 20."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            any_below_20 = False
            for g in parsed.games:
                if not g.turns:
                    continue
                last_turn = g.turns[-1]
                for snap in last_turn.players.values():
                    if snap.life < 20:
                        any_below_20 = True
            assert any_below_20, f"{name}: no player life < 20 across all games"

    def test_life_never_negative_in_fixtures(self) -> None:
        """Sanity check: life should not go below 0 from payment tracking."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                for turn in g.turns:
                    for snap in turn.players.values():
                        assert snap.life >= 0, (
                            f"{name} game {g.game_number} turn {turn.turn_number}: "
                            f"{snap.name} life={snap.life} (negative)"
                        )


# ── ParsedGame model fields ─────────────────────────────────────────────


class TestParsedGameModelFields:
    """Ensure the new fields have correct defaults."""

    def test_default_values(self) -> None:
        from parser_service.parsing.models import ParsedGame

        g = ParsedGame(game_number=1)
        assert g.on_play is None
        assert g.play_first is None
        assert g.opening_hand_sizes == {}

    def test_fields_serialise_roundtrip(self) -> None:
        from parser_service.parsing.models import ParsedGame

        g = ParsedGame(
            game_number=1,
            on_play=True,
            play_first="Alice",
            opening_hand_sizes={"Alice": 7, "Bob": 6},
        )
        data = g.model_dump()
        restored = ParsedGame(**data)
        assert restored.on_play is True
        assert restored.play_first == "Alice"
        assert restored.opening_hand_sizes == {"Alice": 7, "Bob": 6}
