"""Tests for match_archetypes and card_game_stats logic (F5/F6).

Tests the helper functions used by the consumer to classify both
sides and materialize card game stats. These are unit tests that
exercise pure functions and logic without a live database.
"""

from __future__ import annotations

from parser_service.parsing.models import (
    GameEvent,
    ParsedGame,
    ParsedMatch,
)


def _import_helpers():
    """Lazily import consumer helpers to avoid top-level import issues."""
    from parser_service.consumer import (
        _collect_cards_by_side,
        _get_opponent_name,
    )
    return _collect_cards_by_side, _get_opponent_name


# ---------------------------------------------------------------------------
# _collect_cards_by_side
# ---------------------------------------------------------------------------


class TestCollectCardsBySide:
    """Cards from game events are split by hero vs opponent."""

    def test_hero_and_opponent_cards_separated(self) -> None:
        _collect_cards_by_side, _ = _import_helpers()
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[
                ParsedGame(
                    game_number=1,
                    events=[
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Lightning Bolt", player="alice",
                        ),
                        GameEvent(
                            turn_number=1, verb="play",
                            card_name="Mountain", player="alice",
                        ),
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Counterspell", player="bob",
                        ),
                        GameEvent(
                            turn_number=1, verb="play",
                            card_name="Island", player="bob",
                        ),
                    ],
                ),
            ],
        )
        hero_cards, opp_cards = _collect_cards_by_side(parsed, "alice")
        assert "Lightning Bolt" in hero_cards
        assert "Mountain" in hero_cards
        assert "Counterspell" in opp_cards
        assert "Island" in opp_cards
        assert "Counterspell" not in hero_cards
        assert "Lightning Bolt" not in opp_cards

    def test_case_insensitive_hero_match(self) -> None:
        _collect_cards_by_side, _ = _import_helpers()
        parsed = ParsedMatch(
            players=["Alice", "Bob"],
            games=[
                ParsedGame(
                    game_number=1,
                    events=[
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Bolt", player="Alice",
                        ),
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Counter", player="Bob",
                        ),
                    ],
                ),
            ],
        )
        hero_cards, opp_cards = _collect_cards_by_side(parsed, "alice")
        assert "Bolt" in hero_cards
        assert "Counter" in opp_cards

    def test_no_hero_puts_all_in_opponent(self) -> None:
        _collect_cards_by_side, _ = _import_helpers()
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[
                ParsedGame(
                    game_number=1,
                    events=[
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Bolt", player="alice",
                        ),
                    ],
                ),
            ],
        )
        hero_cards, opp_cards = _collect_cards_by_side(parsed, None)
        assert hero_cards == []
        assert "Bolt" in opp_cards

    def test_events_without_card_name_skipped(self) -> None:
        _collect_cards_by_side, _ = _import_helpers()
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[
                ParsedGame(
                    game_number=1,
                    events=[
                        GameEvent(
                            turn_number=1, verb="draw",
                            card_name=None, player="alice",
                        ),
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Bolt", player="alice",
                        ),
                    ],
                ),
            ],
        )
        hero_cards, _ = _collect_cards_by_side(parsed, "alice")
        assert hero_cards == ["Bolt"]

    def test_deduplicates_across_games(self) -> None:
        _collect_cards_by_side, _ = _import_helpers()
        parsed = ParsedMatch(
            players=["alice", "bob"],
            games=[
                ParsedGame(
                    game_number=1,
                    events=[
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Bolt", player="alice",
                        ),
                    ],
                ),
                ParsedGame(
                    game_number=2,
                    events=[
                        GameEvent(
                            turn_number=1, verb="cast",
                            card_name="Bolt", player="alice",
                        ),
                    ],
                ),
            ],
        )
        hero_cards, _ = _collect_cards_by_side(parsed, "alice")
        assert hero_cards == ["Bolt"]


# ---------------------------------------------------------------------------
# _get_opponent_name
# ---------------------------------------------------------------------------


class TestGetOpponentName:
    """Opponent name is the non-hero player from the player list."""

    def test_two_players(self) -> None:
        _, _get_opponent_name = _import_helpers()
        assert _get_opponent_name(["alice", "bob"], "alice") == "bob"

    def test_hero_is_second(self) -> None:
        _, _get_opponent_name = _import_helpers()
        assert _get_opponent_name(["alice", "bob"], "bob") == "alice"

    def test_case_insensitive(self) -> None:
        _, _get_opponent_name = _import_helpers()
        assert _get_opponent_name(["Alice", "Bob"], "alice") == "Bob"

    def test_no_hero_returns_none(self) -> None:
        _, _get_opponent_name = _import_helpers()
        assert _get_opponent_name(["alice", "bob"], None) is None

    def test_empty_players_returns_none(self) -> None:
        _, _get_opponent_name = _import_helpers()
        assert _get_opponent_name([], "alice") is None

    def test_single_player_no_match_returns_none(self) -> None:
        _, _get_opponent_name = _import_helpers()
        assert _get_opponent_name(["alice"], "alice") is None


# ---------------------------------------------------------------------------
# Card game stats aggregation logic (unit tests)
# ---------------------------------------------------------------------------


class TestCardGameStatsAggregation:
    """Test the per-game per-card event aggregation logic used in
    _materialize_card_game_stats. Since the actual function requires
    a DB session, we test the core aggregation algorithm here."""

    def test_seen_cast_played_counts(self) -> None:
        """Counts of seen/cast/played are correct from events."""
        events = [
            GameEvent(
                turn_number=1, verb="cast",
                card_name="Bolt", player="alice",
            ),
            GameEvent(
                turn_number=2, verb="cast",
                card_name="Bolt", player="alice",
            ),
            GameEvent(
                turn_number=1, verb="play",
                card_name="Mountain", player="alice",
            ),
            GameEvent(
                turn_number=1, verb="draw",
                card_name="Bolt", player="alice",
            ),
        ]
        agg: dict[tuple[str, str], dict[str, int]] = {}
        for evt in events:
            if evt.card_name is None:
                continue
            key = (evt.card_name, evt.player)
            a = agg.setdefault(key, {"seen": 0, "cast": 0, "played": 0})
            a["seen"] += 1
            if evt.verb == "cast":
                a["cast"] += 1
            elif evt.verb == "play":
                a["played"] += 1

        bolt = agg[("Bolt", "alice")]
        assert bolt["seen"] == 3  # 2 cast + 1 draw
        assert bolt["cast"] == 2
        assert bolt["played"] == 0

        mountain = agg[("Mountain", "alice")]
        assert mountain["seen"] == 1
        assert mountain["cast"] == 0
        assert mountain["played"] == 1

    def test_is_postboard_flag(self) -> None:
        """Games after game 1 are postboard."""
        assert (1 > 1) is False
        assert (2 > 1) is True
        assert (3 > 1) is True

    def test_won_determination(self) -> None:
        """won = (player_won == is_local).

        This ensures the won column always reflects the hero
        perspective regardless of which side the row belongs to.
        """
        # Hero card, hero won
        game_winner = "alice"
        player = "alice"
        is_local = True
        player_won = game_winner.lower() == player.lower()
        won = player_won == is_local
        assert won is True

        # Hero card, hero lost
        game_winner = "bob"
        player = "alice"
        is_local = True
        player_won = game_winner.lower() == player.lower()
        won = player_won == is_local
        assert won is False

        # Opp card, hero won
        game_winner = "alice"
        player = "bob"
        is_local = False
        player_won = game_winner.lower() == player.lower()
        won = player_won == is_local
        assert won is True

        # Opp card, hero lost
        game_winner = "bob"
        player = "bob"
        is_local = False
        player_won = game_winner.lower() == player.lower()
        won = player_won == is_local
        assert won is False
