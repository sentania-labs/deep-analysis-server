"""Tests for the event-stream parser refactor.

Validates that GameEvent objects are emitted alongside TurnSnapshot
objects, preserving the cast-vs-play verb distinction and capturing
draws, discards, zone moves, and life changes.
"""

from __future__ import annotations

from pathlib import Path

from parser_service.parsing import LogParser
from parser_service.parsing.models import GameEvent

FIXTURES = Path(__file__).parent / "fixtures"

# Real .dat fixtures
DAT_01EA1246 = "Match_GameLog_01ea1246-6306-483b-b03d-d0f7bf203e28.dat"
DAT_2B464924 = "Match_GameLog_2b464924-54fb-4b05-8e3f-d4cfbd9a0310.dat"
DAT_40087184 = "Match_GameLog_40087184-b709-4109-8ee8-7112e894b834.dat"
DAT_4873FBEE = "Match_GameLog_4873fbee-48a8-4830-8864-d5631db75f0b.dat"


def _parse(name: str):
    return LogParser().parse((FIXTURES / name).read_bytes())


# ── basic event emission ───────────────────────────────────────────────


class TestEventEmission:
    """Events are produced for every game that has turns."""

    def test_dat_games_have_events(self) -> None:
        """Every .dat game with turns should also have events."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                if g.turns:
                    assert g.events, f"{name} game {g.game_number}: turns present but events empty"

    def test_text_log_games_have_events(self) -> None:
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        for g in parsed.games:
            if g.turns:
                assert g.events, f"game {g.game_number}: turns present but events empty"

    def test_events_are_game_event_instances(self) -> None:
        parsed = _parse(DAT_01EA1246)
        for g in parsed.games:
            for evt in g.events:
                assert isinstance(evt, GameEvent)

    def test_empty_parse_has_no_events(self) -> None:
        parsed = LogParser().parse(b"")
        assert parsed.games == []


# ── cast vs play distinction ───────────────────────────────────────────


class TestCastPlayDistinction:
    """The core value proposition: cast and play verbs are distinct."""

    def test_dat_has_both_cast_and_play_events(self) -> None:
        """Real .dat fixtures should have both 'cast' and 'play' events."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            verbs = {evt.verb for g in parsed.games for evt in g.events}
            assert "cast" in verbs, f"{name}: no cast events found"
            assert "play" in verbs, f"{name}: no play events found"

    def test_text_log_cast_vs_play(self) -> None:
        """In the text fixture, Mountain is played, Lightning Bolt is cast."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        g1 = parsed.games[0]

        play_events = [e for e in g1.events if e.verb == "play"]
        cast_events = [e for e in g1.events if e.verb == "cast"]

        play_cards = {e.card_name for e in play_events}
        cast_cards = {e.card_name for e in cast_events}

        assert "Mountain" in play_cards, f"Mountain not in play events: {play_cards}"
        assert "Lightning Bolt" in cast_cards, f"Lightning Bolt not in cast events: {cast_cards}"

    def test_dat_lands_are_play_events(self) -> None:
        """In .dat fixtures, lands (Tropical Island, etc.) should be 'play'."""
        parsed = _parse(DAT_01EA1246)
        play_cards: set[str] = set()
        for g in parsed.games:
            for evt in g.events:
                if evt.verb == "play":
                    play_cards.add(evt.card_name or "")
        # Tropical Island is a land played in this fixture
        assert "Tropical Island" in play_cards

    def test_dat_spells_are_cast_events(self) -> None:
        """In .dat fixtures, spells (Force of Will, etc.) should be 'cast'."""
        parsed = _parse(DAT_01EA1246)
        cast_cards: set[str] = set()
        for g in parsed.games:
            for evt in g.events:
                if evt.verb == "cast":
                    cast_cards.add(evt.card_name or "")
        assert "Force of Will" in cast_cards


# ── draw events ────────────────────────────────────────────────────────


class TestDrawEvents:
    """Draw events are captured, including anonymous draws."""

    def test_dat_has_draw_events(self) -> None:
        parsed = _parse(DAT_01EA1246)
        draw_events = [e for g in parsed.games for e in g.events if e.verb == "draw"]
        assert len(draw_events) > 0

    def test_anonymous_draws_have_no_card_name(self) -> None:
        """Anonymous draws (no source card) should have card_name=None."""
        parsed = _parse(DAT_01EA1246)
        anon_draws = [
            e for g in parsed.games for e in g.events if e.verb == "draw" and e.source_card is None
        ]
        assert len(anon_draws) > 0
        for d in anon_draws:
            assert d.card_name is None

    def test_sourced_draws_have_source_card(self) -> None:
        """'draws a card with Brainstorm' should populate source_card."""
        parsed = _parse(DAT_01EA1246)
        sourced = [
            e
            for g in parsed.games
            for e in g.events
            if e.verb == "draw" and e.source_card is not None
        ]
        assert len(sourced) > 0
        source_names = {e.source_card for e in sourced}
        # These fixtures have Brainstorm draws
        assert any("Brainstorm" in s for s in source_names if s), (
            f"No Brainstorm source: {source_names}"
        )

    def test_text_log_draw_events(self) -> None:
        """Text log fixture doesn't have explicit draws, but exercises the path."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        # Text fixture does not have draw lines, so we just verify no crash
        assert parsed.games


# ── zone move events ───────────────────────────────────────────────────


class TestZoneMoveEvents:
    """Graveyard and exile events are captured."""

    def test_dat_graveyard_events(self) -> None:
        parsed = _parse(DAT_01EA1246)
        gy_events = [e for g in parsed.games for e in g.events if e.verb == "graveyard"]
        assert len(gy_events) > 0
        gy_cards = {e.card_name for e in gy_events}
        assert "Flusterstorm" in gy_cards

    def test_dat_exile_events(self) -> None:
        parsed = _parse(DAT_01EA1246)
        exile_events = [e for g in parsed.games for e in g.events if e.verb == "exile"]
        assert len(exile_events) > 0
        exile_cards = {e.card_name for e in exile_events}
        assert "Atraxa, Grand Unifier" in exile_cards

    def test_text_log_discard_events(self) -> None:
        """Text fixture has Bob discarding Forest."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        g1 = parsed.games[0]
        discard_events = [e for e in g1.events if e.verb == "discard"]
        assert len(discard_events) > 0
        assert any(e.card_name == "Forest" and e.player == "Bob" for e in discard_events)

    def test_text_log_graveyard_zone_move(self) -> None:
        """'Forest is put into Bob's graveyard' should produce a graveyard event."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        g1 = parsed.games[0]
        gy_events = [e for e in g1.events if e.verb == "graveyard"]
        assert any(e.card_name == "Forest" for e in gy_events)


# ── life change events ─────────────────────────────────────────────────


class TestLifeChangeEvents:
    """Life payments produce life_change events."""

    def test_dat_life_change_events(self) -> None:
        """Force of Will casts with life payment should emit life_change."""
        parsed = _parse(DAT_01EA1246)
        lc_events = [e for g in parsed.games for e in g.events if e.verb == "life_change"]
        assert len(lc_events) > 0

    def test_text_log_damage_events(self) -> None:
        """Lightning Bolt dealing 3 damage should produce a damage event."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        g1 = parsed.games[0]
        dmg_events = [e for e in g1.events if e.verb == "damage"]
        assert len(dmg_events) > 0
        assert any(e.player == "Bob" for e in dmg_events)

    def test_text_log_life_delta_events(self) -> None:
        """'Bob loses 3 life' should produce a life_change event."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        g2 = parsed.games[1]
        lc_events = [e for e in g2.events if e.verb == "life_change"]
        assert len(lc_events) > 0
        assert any(e.player == "Bob" for e in lc_events)


# ── event metadata ─────────────────────────────────────────────────────


class TestEventMetadata:
    """Events carry correct turn numbers and player names."""

    def test_events_have_valid_turn_numbers(self) -> None:
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                for evt in g.events:
                    assert evt.turn_number >= 1, f"bad turn_number: {evt}"

    def test_events_have_canonical_player_names(self) -> None:
        """Event player names should be from the match's canonical player set."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            canonical = set(parsed.players)
            for g in parsed.games:
                for evt in g.events:
                    assert evt.player in canonical, (
                        f"{name}: event player '{evt.player}' not in {canonical}"
                    )

    def test_events_have_valid_verbs(self) -> None:
        valid_verbs = {
            "cast",
            "play",
            "draw",
            "discard",
            "exile",
            "graveyard",
            "damage",
            "life_change",
            "mana_float",
        }
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                for evt in g.events:
                    assert evt.verb in valid_verbs, f"unexpected verb: {evt.verb}"

    def test_card_names_are_clean(self) -> None:
        """No @-artifacts in event card names."""
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                for evt in g.events:
                    if evt.card_name:
                        assert "@" not in evt.card_name, f"dirty card name: {evt.card_name}"
                    if evt.source_card:
                        assert "@" not in evt.source_card, f"dirty source_card: {evt.source_card}"


# ── snapshot backward compatibility ────────────────────────────────────


class TestSnapshotBackwardCompat:
    """Existing TurnSnapshot output is unchanged by the event refactor."""

    def test_turns_still_populated(self) -> None:
        for name in (DAT_01EA1246, DAT_2B464924, DAT_40087184, DAT_4873FBEE):
            parsed = _parse(name)
            for g in parsed.games:
                assert g.turns, f"{name} game {g.game_number}: no turns"

    def test_battlefield_still_populated(self) -> None:
        """Cards still appear on the battlefield via snapshots."""
        parsed = _parse(DAT_01EA1246)
        cards: set[str] = set()
        for g in parsed.games:
            for turn in g.turns:
                for snap in turn.players.values():
                    cards.update(snap.zones.battlefield)
        assert "Force of Will" in cards
        assert "Tropical Island" in cards

    def test_graveyard_still_populated(self) -> None:
        parsed = _parse(DAT_01EA1246)
        last_turn = parsed.games[0].turns[-1]
        assert "Flusterstorm" in last_turn.players["WANGSU"].zones.graveyard

    def test_exile_still_populated(self) -> None:
        parsed = _parse(DAT_01EA1246)
        last_turn = parsed.games[0].turns[-1]
        assert "Atraxa, Grand Unifier" in last_turn.players["sentania"].zones.exile

    def test_life_payments_still_tracked(self) -> None:
        parsed = _parse(DAT_01EA1246)
        last_turn = parsed.games[0].turns[-1]
        assert last_turn.players["WANGSU"].life < 20

    def test_text_log_snapshot_unchanged(self) -> None:
        """Text fixture regression: turns, battlefield, life, mana, stack."""
        parsed = LogParser().parse((FIXTURES / "match_2_0_modern.log").read_bytes())
        g1 = parsed.games[0]
        assert len(g1.turns) >= 4
        t1 = g1.turns[0]
        assert t1.turn_number == 1
        assert t1.active_player == "Alice"
        assert t1.players["Bob"].life == 17
        assert "Mountain" in t1.players["Alice"].zones.battlefield


# ── ParsedGame model defaults ──────────────────────────────────────────


class TestParsedGameEventsField:
    """The new events field has a correct default."""

    def test_default_is_empty_list(self) -> None:
        from parser_service.parsing.models import ParsedGame

        g = ParsedGame(game_number=1)
        assert g.events == []

    def test_events_serialise_roundtrip(self) -> None:
        from parser_service.parsing.models import ParsedGame

        evt = GameEvent(turn_number=1, verb="cast", card_name="Lightning Bolt", player="Alice")
        g = ParsedGame(game_number=1, events=[evt])
        data = g.model_dump()
        restored = ParsedGame(**data)
        assert len(restored.events) == 1
        assert restored.events[0].verb == "cast"
        assert restored.events[0].card_name == "Lightning Bolt"
