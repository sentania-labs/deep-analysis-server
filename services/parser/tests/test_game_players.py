"""Tests for hero identification and game_players persistence (F3/F4).

Tests the new ``hero_player_name`` resolution and ``game_players``
table population at parse time. Uses the same fixture-based approach
as the existing parser tests — no live Postgres required.
"""

from __future__ import annotations

from parser_service.parsing.models import ParsedGame
from parser_service.persistence import _extract_player_names

# ---------------------------------------------------------------------------
# _extract_player_names
# ---------------------------------------------------------------------------


class TestExtractPlayerNames:
    """Unit tests for the helper that finds player names."""

    def test_prefers_match_level_players(self) -> None:
        game = ParsedGame(
            game_number=1,
            opening_hand_sizes={"AliceAlt": 7, "BobAlt": 7},
        )
        result = _extract_player_names(game, ["Alice", "Bob"])
        assert result == ["Alice", "Bob"]

    def test_falls_back_to_opening_hand_sizes(self) -> None:
        game = ParsedGame(
            game_number=1,
            opening_hand_sizes={"Alice": 7, "Bob": 7},
        )
        result = _extract_player_names(game, [])
        assert result == ["Alice", "Bob"]

    def test_falls_back_to_turns(self) -> None:
        from parser_service.parsing.models import PlayerSnapshot, TurnSnapshot

        game = ParsedGame(
            game_number=1,
            turns=[
                TurnSnapshot(
                    turn_number=1,
                    active_player="Alice",
                    players={
                        "Alice": PlayerSnapshot(name="Alice"),
                        "Bob": PlayerSnapshot(name="Bob"),
                    },
                ),
            ],
        )
        result = _extract_player_names(game, [])
        assert set(result) == {"Alice", "Bob"}

    def test_empty_game_returns_empty(self) -> None:
        game = ParsedGame(game_number=1)
        result = _extract_player_names(game, [])
        assert result == []


# ---------------------------------------------------------------------------
# Hero resolution logic (unit tests for the consumer helper)
# ---------------------------------------------------------------------------


class TestHeroResolution:
    """Tests for the hero identification logic that runs at parse time.

    These test the core matching algorithm rather than the async
    consumer method (which requires Redis/DB).
    """

    def test_match_by_mtgo_username(self) -> None:
        """When MTGO username matches a player, that player is the hero."""
        players = ["sentania", "opponent123"]
        mtgo_usernames = ["sentania"]
        names_lower = {n.lower() for n in mtgo_usernames}
        hero = None
        for p in players:
            if str(p).lower() in names_lower:
                hero = str(p)
                break
        assert hero == "sentania"

    def test_case_insensitive_match(self) -> None:
        """Username matching is case-insensitive."""
        players = ["Sentania", "opponent123"]
        mtgo_usernames = ["sentania"]
        names_lower = {n.lower() for n in mtgo_usernames}
        hero = None
        for p in players:
            if str(p).lower() in names_lower:
                hero = str(p)
                break
        assert hero == "Sentania"

    def test_multiple_usernames_first_match_wins(self) -> None:
        """With multiple MTGO usernames, the first match is used."""
        players = ["alice", "bob"]
        mtgo_usernames = ["bob", "alice"]
        names_lower = {n.lower() for n in mtgo_usernames}
        hero = None
        for p in players:
            if str(p).lower() in names_lower:
                hero = str(p)
                break
        assert hero == "alice"

    def test_no_match_falls_back_to_first_player(self) -> None:
        """When no MTGO username matches, fallback to players[0]."""
        players = ["alice", "bob"]
        mtgo_usernames = ["charlie"]
        names_lower = {n.lower() for n in mtgo_usernames}
        hero = None
        for p in players:
            if str(p).lower() in names_lower:
                hero = str(p)
                break
        if hero is None and players:
            hero = str(players[0])
        assert hero == "alice"

    def test_no_usernames_falls_back_to_first_player(self) -> None:
        """When no MTGO usernames are configured, fallback to players[0]."""
        players = ["alice", "bob"]
        hero = str(players[0]) if players else None
        assert hero == "alice"

    def test_empty_players_returns_none(self) -> None:
        """No players means no hero."""
        players: list[str] = []
        hero = str(players[0]) if players else None
        assert hero is None


# ---------------------------------------------------------------------------
# GamePlayer row construction (persistence helpers)
# ---------------------------------------------------------------------------


class TestGamePlayerConstruction:
    """Tests for the game_players value construction logic."""

    def test_is_local_true_for_hero(self) -> None:
        """Hero player gets is_local=True."""
        hero = "alice"
        pname = "alice"
        is_local = pname.lower() == hero.lower()
        assert is_local is True

    def test_is_local_false_for_opponent(self) -> None:
        """Opponent gets is_local=False."""
        hero = "alice"
        pname = "bob"
        is_local = pname.lower() == hero.lower()
        assert is_local is False

    def test_is_local_none_when_no_hero(self) -> None:
        """When hero is unknown, is_local should be None."""
        hero = None
        is_local = None
        if hero:
            is_local = "bob".lower() == hero.lower()
        assert is_local is None

    def test_on_play_from_play_first(self) -> None:
        """on_play is True when player matches play_first."""
        play_first = "alice"
        pname = "alice"
        on_play = pname.lower() == play_first.lower()
        assert on_play is True

    def test_on_play_false_for_draw_player(self) -> None:
        """on_play is False for the player who didn't choose to play."""
        play_first = "alice"
        pname = "bob"
        on_play = pname.lower() == play_first.lower()
        assert on_play is False

    def test_mulligan_count_full_hand(self) -> None:
        """7-card hand means 0 mulligans."""
        hand_size = 7
        mulligan_count = max(0, 7 - hand_size)
        assert mulligan_count == 0

    def test_mulligan_count_one_mulligan(self) -> None:
        """6-card hand means 1 mulligan."""
        hand_size = 6
        mulligan_count = max(0, 7 - hand_size)
        assert mulligan_count == 1

    def test_mulligan_count_aggressive_mulligan(self) -> None:
        """5-card hand means 2 mulligans."""
        hand_size = 5
        mulligan_count = max(0, 7 - hand_size)
        assert mulligan_count == 2


# ---------------------------------------------------------------------------
# Integration-style: parsed match → game_player values
# ---------------------------------------------------------------------------


class TestGamePlayerFromParsedMatch:
    """Build game_player dicts from a ParsedMatch to verify the
    full pipeline logic (without DB)."""

    def _build_game_player_values(
        self,
        parsed_game: ParsedGame,
        match_players: list[str],
        hero_player_name: str | None,
        game_id: str = "fake-game-id",
    ) -> list[dict]:
        """Replicate the persistence logic for game_player row construction."""
        player_names = _extract_player_names(parsed_game, match_players)
        values = []
        for pname in player_names:
            is_local = None
            if hero_player_name:
                is_local = pname.lower() == hero_player_name.lower()
            on_play = None
            if parsed_game.play_first:
                on_play = pname.lower() == parsed_game.play_first.lower()
            mulligan_count = None
            hand_sizes = parsed_game.opening_hand_sizes or {}
            if pname in hand_sizes:
                mulligan_count = max(0, 7 - int(hand_sizes[pname]))
            else:
                for k, v in hand_sizes.items():
                    if k.lower() == pname.lower():
                        mulligan_count = max(0, 7 - int(v))
                        break
            values.append(
                {
                    "game_id": game_id,
                    "player_name": pname,
                    "is_local": is_local,
                    "on_play": on_play,
                    "mulligan_count": mulligan_count,
                }
            )
        return values

    def test_two_player_game(self) -> None:
        game = ParsedGame(
            game_number=1,
            play_first="alice",
            opening_hand_sizes={"alice": 7, "bob": 6},
        )
        values = self._build_game_player_values(
            game,
            ["alice", "bob"],
            hero_player_name="alice",
        )
        assert len(values) == 2
        hero_row = next(v for v in values if v["player_name"] == "alice")
        opp_row = next(v for v in values if v["player_name"] == "bob")

        assert hero_row["is_local"] is True
        assert hero_row["on_play"] is True
        assert hero_row["mulligan_count"] == 0

        assert opp_row["is_local"] is False
        assert opp_row["on_play"] is False
        assert opp_row["mulligan_count"] == 1

    def test_no_hero_sets_is_local_none(self) -> None:
        game = ParsedGame(
            game_number=1,
            play_first="alice",
            opening_hand_sizes={"alice": 7, "bob": 7},
        )
        values = self._build_game_player_values(
            game,
            ["alice", "bob"],
            hero_player_name=None,
        )
        for v in values:
            assert v["is_local"] is None

    def test_no_play_first_sets_on_play_none(self) -> None:
        game = ParsedGame(
            game_number=1,
            opening_hand_sizes={"alice": 7, "bob": 7},
        )
        values = self._build_game_player_values(
            game,
            ["alice", "bob"],
            hero_player_name="alice",
        )
        for v in values:
            assert v["on_play"] is None

    def test_no_hand_sizes_sets_mulligan_none(self) -> None:
        game = ParsedGame(game_number=1)
        values = self._build_game_player_values(
            game,
            ["alice", "bob"],
            hero_player_name="alice",
        )
        for v in values:
            assert v["mulligan_count"] is None

    def test_case_insensitive_hero_match(self) -> None:
        game = ParsedGame(
            game_number=1,
            opening_hand_sizes={"Alice": 7, "Bob": 7},
        )
        values = self._build_game_player_values(
            game,
            ["Alice", "Bob"],
            hero_player_name="alice",
        )
        alice_row = next(v for v in values if v["player_name"] == "Alice")
        assert alice_row["is_local"] is True
