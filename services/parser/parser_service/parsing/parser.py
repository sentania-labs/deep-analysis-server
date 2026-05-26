"""MTGO log parser — strategy-pattern facade.

Two layers:

* :class:`LogFormatStrategy` — protocol/abstract. Implementations
  decide whether they can parse a given payload and produce a
  :class:`ParsedMatch`. Today: :class:`MTGODatStrategy` for MTGO's
  binary-framed ``Match_GameLog_*.dat`` files plus
  :class:`MTGOTextLogStrategy` for plaintext logs.
* :class:`LogParser` — orchestrator. Walks its strategy list, picks
  the first one that claims it can handle the payload, and runs it.

Both strategies are intentionally forgiving: MTGO's log format
varies and best-effort extraction is more useful than exceptions.
Missing data shows up as ``None`` / empty rather than parse failures.
"""

from __future__ import annotations

import re
import struct
from abc import ABC, abstractmethod
from collections import Counter
from datetime import UTC, datetime

from parser_service.parsing.models import (
    GameEvent,
    ManaPool,
    ParsedGame,
    ParsedMatch,
    PlayerSnapshot,
    PlayerZones,
    StackEntry,
    TurnSnapshot,
)

# --- text-log regex patterns ----------------------------------------------

_FORMAT_RE = re.compile(
    r"format[:\s]+(?P<fmt>modern|legacy|vintage|pioneer|standard|pauper|"
    r"commander|draft|sealed|historic|premodern|cube)",
    re.IGNORECASE,
)
_EVENT_RE = re.compile(r"event(?:\s*type)?[:\s]+(?P<evt>[A-Za-z0-9 _\-]+)", re.IGNORECASE)
_MATCH_ID_RE = re.compile(r"match\s*(?:id)?[:#\s]+(?P<id>[A-Za-z0-9_\-]+)", re.IGNORECASE)
_PLAYERS_RE = re.compile(
    r"^\s*players?\s*[:\s]\s*(?P<players>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_GAME_HEADER_RE = re.compile(
    r"^[\s\-=]*game\s+(?P<num>\d+)\b.*$",
    re.IGNORECASE | re.MULTILINE,
)
_TURN_RE = re.compile(
    r"^[\s\-=]*turn\s+(?P<num>\d+)\s*(?:\((?P<player>[^)]+)\))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_LIFE_RE = re.compile(
    r"^(?P<player>[^:\n]+?)(?:'s)?\s+life(?:\s+total)?\s*[:\s]\s*(?P<life>-?\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_LIFE_DELTA_RE = re.compile(
    r"^(?P<player>[^\n]+?)\s+(?P<verb>gains?|loses?)\s+(?P<amt>\d+)\s+life",
    re.IGNORECASE | re.MULTILINE,
)
_DAMAGE_RE = re.compile(
    r"^(?P<source>[^\n]+?)\s+deals\s+(?P<amt>\d+)\s+damage\s+to\s+(?P<target>[^\n.]+?)[.\s]*$",
    re.IGNORECASE | re.MULTILINE,
)
_PLAY_RE = re.compile(
    r"^(?P<player>[^\n]+?)\s+(?:plays|casts|activates)\s+(?P<card>[A-Z][^\n.]+?)"
    r"(?:\s+targeting\s+(?P<target>[^\n.]+?))?[.\s]*$",
    re.MULTILINE,
)
_DRAW_RE = re.compile(
    r"^(?P<player>[^\n]+?)\s+draws?\s+(?:a\s+card|(?P<card>[A-Z][^\n.]+?))[.\s]*$",
    re.MULTILINE,
)
_DISCARD_RE = re.compile(
    r"^(?P<player>[^\n]+?)\s+discards?\s+(?P<card>[A-Z][^\n.]+?)[.\s]*$",
    re.MULTILINE,
)
_ZONE_MOVE_RE = re.compile(
    r"^(?P<card>[A-Z][^\n]+?)\s+is\s+(?:put|moved)\s+(?:into|to)\s+"
    r"(?P<player>[^\n]+?)'s\s+(?P<zone>graveyard|exile|hand|library|battlefield)\b",
    re.IGNORECASE | re.MULTILINE,
)
_GAME_WIN_RE = re.compile(
    r"(?P<player>\S[^\n]*?)\s+wins\s+game\s+(?P<num>\d+)",
    re.IGNORECASE,
)
_GAME_RESULT_RE = re.compile(
    r"game\s+(?P<num>\d+)\s+(?:result\s*[:\s])?\s*(?P<result>concede[d]?|draw|win|loss)",
    re.IGNORECASE,
)
_MATCH_WIN_RE = re.compile(
    r"(?P<player>\S[^\n]*?)\s+wins\s+the\s+match(?:\s+(?P<score>\d+\s*-\s*\d+))?",
    re.IGNORECASE,
)
_MATCH_LOSE_RE = re.compile(r"(?P<player>\S[^\n]*?)\s+loses\s+the\s+match", re.IGNORECASE)
_MATCH_CONCEDE_RE = re.compile(
    r"(?P<player>\S[^\n]*?)\s+has\s+conceded\s+from\s+the\s+match",
    re.IGNORECASE,
)
_MANA_FLOAT_RE = re.compile(
    r"^(?P<player>[^\n]+?)\s+(?:has|now\s+has)\s+(?P<pool>[WUBRGC0-9]+)"
    r"\s+(?:in(?:\s+(?:their|his|her))?\s+)?mana\s+pool",
    re.IGNORECASE | re.MULTILINE,
)
_STACK_RE = re.compile(
    r"^stack\s*[:\s]\s*(?P<contents>.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _normalize_player(name: str) -> str:
    return name.strip().rstrip(":,").strip()


def _split_players(line: str) -> list[str]:
    parts = re.split(r"\s*(?:,| vs\.? | versus )\s*", line, flags=re.IGNORECASE)
    return [_normalize_player(p) for p in parts if p.strip()]


def _parse_mana_string(pool: str) -> ManaPool:
    """Turn a string like ``WUB2`` into a :class:`ManaPool`."""
    mp = ManaPool()
    i = 0
    while i < len(pool):
        ch = pool[i]
        if ch in "WUBRGC":
            setattr(mp, ch, getattr(mp, ch) + 1)
            i += 1
        elif ch.isdigit():
            j = i
            while j < len(pool) and pool[j].isdigit():
                j += 1
            mp.C += int(pool[i:j])
            i = j
        else:
            i += 1
    return mp


class LogFormatStrategy(ABC):
    """One implementation per concrete log format."""

    @abstractmethod
    def can_parse(self, content: bytes, filename: str | None = None) -> bool:
        """Return True if this strategy claims it can parse the payload."""

    @abstractmethod
    def parse(self, content: bytes) -> ParsedMatch:
        """Parse the payload, returning a best-effort :class:`ParsedMatch`."""


class MTGODatStrategy(LogFormatStrategy):
    """Parser for MTGO ``Match_GameLog_<uuid>.dat`` game logs.

    The format is text with binary framing: each log line is preceded
    by an ~8-byte binary header (timestamp + length) and the literal
    bytes ``@P`` (or ``@P@P`` for join lines). After stripping bytes
    outside printable ASCII (plus newline/CR), the result is roughly
    ``junk@PLINE@PLINE...`` where each LINE is real log text and the
    ``junk`` between is whatever printable bytes survived from the
    next frame's binary header.

    The strategy works by scanning the filtered text for ``@P``-anchored
    patterns (joins, turn headers, game/match wins, plays, casts). The
    join and turn-header patterns establish canonical player names,
    which are then used as a closed alternation in the more permissive
    patterns to keep trailing junk bytes out of captures.
    """

    _CAN_PARSE_HINTS: tuple[bytes, ...] = (
        b"joined the game.",
        b"@[",
    )
    _CAN_PARSE_UUID_RE = re.compile(rb"\$[0-9a-f-]{36}", re.IGNORECASE)

    # Header for the dollar-prefixed match-id record. Anchored at line
    # start because the file opens with ``$<uuid>$<uuid>...`` before any
    # binary frames begin.
    _UUID_RE = re.compile(r"\$([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

    # Join lines are double-prefixed with ``@P@P``. Distinguishing them
    # is what gives us a reliable list of canonical player names.
    _JOIN_RE = re.compile(r"@P@P(.+?) joined the game\.")

    _CARD_RE = re.compile(r"@\[([^@\[\]]+?)@:\d+,\d+:@\]")

    # --- word-to-int mapping for MTGO hand-size text ----------------------
    _WORD_TO_INT: dict[str, int] = {
        "zero": 0,
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
    }

    def can_parse(self, content: bytes, filename: str | None = None) -> bool:
        if not content:
            return False
        sample = content[: 64 * 1024]
        if self._CAN_PARSE_UUID_RE.search(sample):
            return True
        return any(hint in sample for hint in self._CAN_PARSE_HINTS)

    # .NET epoch offset in 100-ns ticks from Jan 1, 0001 to Unix epoch (Jan 1, 1970).
    _DOTNET_EPOCH_OFFSET_TICKS: int = 621_355_968_000_000_000
    # File header size: 2 bytes (01 00) + 37 bytes UUID + 2 bytes (04 00) + 37 bytes UUID = 78
    _FILE_HEADER_SIZE: int = 78

    @staticmethod
    def _extract_played_at(content: bytes) -> datetime | None:
        """Extract the first frame's .NET timestamp and return it as a UTC datetime.

        The binary format after the 78-byte file header is:
          8-byte LE int64 (.NET ticks) | 2-byte BE uint16 (message length) | message bytes

        .NET ticks are 100-nanosecond intervals since January 1, 0001.
        """
        try:
            offset = MTGODatStrategy._FILE_HEADER_SIZE
            if len(content) < offset + 8:
                return None
            (ticks,) = struct.unpack_from("<q", content, offset)
            unix_ts = (ticks - MTGODatStrategy._DOTNET_EPOCH_OFFSET_TICKS) / 10_000_000
            return datetime.fromtimestamp(unix_ts, tz=UTC)
        except Exception:  # noqa: BLE001
            return None

    def parse(self, content: bytes) -> ParsedMatch:
        text = self._strip_binary(content)
        match = ParsedMatch()

        match.played_at = self._extract_played_at(content)

        if (m := self._UUID_RE.search(text)) is not None:
            match.raw_match_id = m.group(1)

        # Canonical players: ordered by first appearance in joins.
        seen_order: list[str] = []
        seen_set: set[str] = set()
        for m in self._JOIN_RE.finditer(text):
            name = m.group(1)
            if name not in seen_set:
                seen_set.add(name)
                seen_order.append(name)
        match.players = seen_order

        match_winner, match_score, match_tied = self._extract_match_result(text, seen_order)
        match.match_result = match_score
        match.match_tied = match_tied
        match.winner = None if match_tied else match_winner

        match.games = self._parse_games(text, seen_order)

        # Fallback: infer match winner from per-game results when the
        # log is truncated (no "wins the match" line).  Skip when the
        # match was explicitly tied — None is the correct winner for
        # ties. Require strictly more wins than the runner-up so equal
        # game counts (e.g. 1-1 unfinished) don't produce a false
        # positive.
        if match.winner is None and not match_tied and match.games:
            wins: Counter[str] = Counter()
            for g in match.games:
                if g.winner:
                    wins[g.winner] += 1
            if wins:
                best_player, best_count = wins.most_common(1)[0]
                opp_count = max((c for p, c in wins.items() if p != best_player), default=0)
                if best_count >= 2 and best_count > opp_count:
                    match.winner = best_player
                    match.match_result = f"{best_count}-{opp_count}"

        # Synthesize a score when the winner was resolved (e.g. from a
        # match-level concession) but no score string was captured.
        if match.winner and not match.match_result and match.games:
            w_count = sum(1 for g in match.games if g.winner == match.winner)
            l_count = sum(1 for g in match.games if g.winner and g.winner != match.winner)
            if w_count or l_count:
                match.match_result = f"{w_count}-{l_count}"

        return match

    @staticmethod
    def _strip_binary(content: bytes) -> str:
        """Drop bytes outside printable ASCII (plus newline/CR) and decode.

        High-bit bytes (0x80+) are part of the binary framing and never
        contain real log content; dropping them leaves clean ASCII the
        regexes can anchor against.
        """
        cleaned = bytes(b for b in content if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D))
        return cleaned.decode("ascii", errors="replace")

    @staticmethod
    def _player_alt(players: list[str]) -> str:
        """Build a regex alternation matching any canonical player name.

        Sorted longest-first so prefix names don't shadow longer ones
        (e.g. ``foo`` shouldn't win over ``foobar``).
        """
        if not players:
            # Fallback that still terminates on whitespace/punctuation —
            # used when joins didn't yield any player names.
            return r"[A-Za-z0-9_][A-Za-z0-9_-]*"
        alts = sorted(players, key=len, reverse=True)
        return "|".join(re.escape(p) for p in alts)

    def _extract_match_result(
        self, text: str, players: list[str]
    ) -> tuple[str | None, str | None, bool]:
        """Return ``(winner, score, tied)`` extracted from the match-result line.

        Score components are bound to single digits to stop the regex
        from greedily eating trailing binary-header bytes that decoded
        to digits.
        """
        alt = self._player_alt(players)
        win_re = re.compile(rf"@P({alt}) wins the match (\d)-(\d)")
        if (m := win_re.search(text)) is not None:
            score = f"{m.group(2)}-{m.group(3)}"
            return m.group(1), score, False
        # Match-level concession: "@P<player> has conceded from the match."
        # The conceder loses; opponent is the winner. No score is given in
        # the log so we leave it None for the fallback to synthesize from
        # per-game results.
        concede_match_re = re.compile(rf"@P({alt}) has conceded from the match\.")
        if (m := concede_match_re.search(text)) is not None:
            conceder = m.group(1)
            winner = next((p for p in players if p != conceder), None)
            return winner, None, False
        # ``Match Tied`` lines are not @P-prefixed in the raw stream.
        tie_re = re.compile(r"Match Tied (\d)-(\d)")
        if (m := tie_re.search(text)) is not None:
            return None, f"{m.group(1)}-{m.group(2)}", True
        return None, None, False

    def _parse_games(self, text: str, players: list[str]) -> list[ParsedGame]:
        """Split text by join-pair boundaries, parse each game block.

        Each game opens with a fresh pair of ``@P@P<player> joined``
        lines, so a game block runs from the first join of pair N to
        the first join of pair N+1 (or EOF for the last game).
        """
        if not players:
            return []

        join_positions = [m.start() for m in self._JOIN_RE.finditer(text)]
        if not join_positions:
            return []

        # Pair joins: pair k = positions[2k], positions[2k+1].
        pair_count = len(join_positions) // 2
        if pair_count == 0:
            return []

        games: list[ParsedGame] = []
        for game_idx in range(pair_count):
            block_start = join_positions[game_idx * 2]
            if game_idx + 1 < pair_count:
                block_end = join_positions[(game_idx + 1) * 2]
            else:
                block_end = len(text)
            block = text[block_start:block_end]
            games.append(self._parse_game_block(game_idx + 1, block, players))
        return games

    def _parse_game_block(self, game_number: int, block: str, players: list[str]) -> ParsedGame:
        game = ParsedGame(game_number=game_number)
        alt = self._player_alt(players)

        win_game_re = re.compile(rf"@P({alt}) wins the game\.")
        concede_re = re.compile(rf"@P({alt}) has conceded from the game\.")

        if (m := win_game_re.search(block)) is not None:
            game.winner = m.group(1)
            game.result = "win"
        elif (m := concede_re.search(block)) is not None:
            conceder = m.group(1)
            opp = next((p for p in players if p != conceder), None)
            game.winner = opp
            game.result = "concede"

        # --- play/draw detection ------------------------------------------
        play_first_re = re.compile(rf"@P({alt}) chooses to play first\.")
        draw_first_re = re.compile(rf"@P({alt}) chooses to draw first\.")
        if (m := play_first_re.search(block)) is not None:
            game.play_first = m.group(1)
        elif (m := draw_first_re.search(block)) is not None:
            # The player who chose to draw first means the opponent plays first.
            chooser = m.group(1)
            opp = next((p for p in players if p != chooser), None)
            game.play_first = opp

        # --- opening hand sizes -------------------------------------------
        # Two forms in the .dat log:
        #   "@P<player> begins the game with <word> cards in hand."
        #   "@P<player> puts ... and begins the game with <word> cards in hand."
        # Both indicate the final hand size (post-mulligan). We use two
        # separate patterns so the non-greedy quantifier can't skip across
        # @P boundaries.
        word_alt = "|".join(self._WORD_TO_INT.keys())
        hand_direct_re = re.compile(rf"@P({alt}) begins the game with ({word_alt}) cards in hand\.")
        hand_bottom_re = re.compile(
            rf"@P({alt}) puts [^@]+ and begins the game with ({word_alt}) cards in hand\."
        )
        for m in hand_direct_re.finditer(block):
            player = m.group(1)
            count = self._WORD_TO_INT.get(m.group(2).lower(), 7)
            game.opening_hand_sizes[player] = count
        for m in hand_bottom_re.finditer(block):
            player = m.group(1)
            count = self._WORD_TO_INT.get(m.group(2).lower(), 7)
            # The "puts ... and begins" form is the post-mulligan size;
            # it overrides any earlier "begins the game" match.
            game.opening_hand_sizes[player] = count

        # on_play is relative to the first player in the match's player
        # list (the "hero"): True if hero plays first, False if hero draws.
        # We leave it None if we couldn't determine play_first.
        if game.play_first is not None and players:
            game.on_play = game.play_first == players[0]

        game.turns, game.events = self._parse_turns(block, players)
        return game

    def _parse_turns(
        self, block: str, players: list[str]
    ) -> tuple[list[TurnSnapshot], list[GameEvent]]:
        alt = self._player_alt(players)
        turn_re = re.compile(rf"@PTurn (\d+): ({alt})")
        marks = [(m.start(), int(m.group(1)), m.group(2)) for m in turn_re.finditer(block)]
        if not marks:
            return [], []

        carry: dict[str, PlayerSnapshot] = {p: PlayerSnapshot(name=p) for p in players}
        card_pat = self._CARD_RE.pattern

        play_re = re.compile(rf"@P({alt}) plays {card_pat}")
        cast_re = re.compile(rf"@P({alt}) casts {card_pat}")

        # Draw patterns:
        #   "@P<player> draws a card."  (anonymous draw)
        #   "@P<player> draws a card with @[Card@:id:@]."  (draw triggered by source)
        #   "@P<player> draws <word> cards with @[Card@:id:@]."  (multi-draw)
        draw_anon_re = re.compile(rf"@P({alt}) draws a card\.")
        draw_with_re = re.compile(rf"@P({alt}) draws a card with {card_pat}")
        draw_multi_re = re.compile(
            rf"@P({alt}) draws ({'|'.join(self._WORD_TO_INT.keys())})"
            rf" cards with {card_pat}"
        )

        # Graveyard: "@P<player> puts @[Card@:id:@] into their graveyard."
        graveyard_re = re.compile(rf"@P({alt}) puts {card_pat} into their graveyard\.")

        # Exile: "@P<player> exiles @[Card@:id:@]"
        exile_re = re.compile(rf"@P({alt}) exiles {card_pat}")

        # Life payment: "by paying <N> life" within a cast line.
        # The player is captured from the cast-line prefix.
        life_pay_re = re.compile(rf"@P({alt}) casts {card_pat} by paying (\d+) life")

        turns: list[TurnSnapshot] = []
        events: list[GameEvent] = []
        for idx, (start, num, active) in enumerate(marks):
            end = marks[idx + 1][0] if idx + 1 < len(marks) else len(block)
            window = block[start:end]

            # Lands → battlefield + "play" event
            for pm in play_re.finditer(window):
                snap = carry.setdefault(pm.group(1), PlayerSnapshot(name=pm.group(1)))
                card = pm.group(2).strip()
                snap.zones.battlefield.append(card)
                events.append(
                    GameEvent(turn_number=num, verb="play", card_name=card, player=pm.group(1))
                )

            # Spells → battlefield + "cast" event
            for cm in cast_re.finditer(window):
                snap = carry.setdefault(cm.group(1), PlayerSnapshot(name=cm.group(1)))
                card = cm.group(2).strip()
                snap.zones.battlefield.append(card)
                events.append(
                    GameEvent(turn_number=num, verb="cast", card_name=card, player=cm.group(1))
                )

            # Draws → hand zone + "draw" events
            for dm in draw_anon_re.finditer(window):
                snap = carry.setdefault(dm.group(1), PlayerSnapshot(name=dm.group(1)))
                snap.zones.hand.append("unknown")
                events.append(
                    GameEvent(turn_number=num, verb="draw", card_name=None, player=dm.group(1))
                )
            for dm in draw_with_re.finditer(window):
                snap = carry.setdefault(dm.group(1), PlayerSnapshot(name=dm.group(1)))
                snap.zones.hand.append("unknown")
                source = dm.group(2).strip()
                events.append(
                    GameEvent(
                        turn_number=num,
                        verb="draw",
                        card_name=None,
                        player=dm.group(1),
                        source_card=source,
                    )
                )
            for dm in draw_multi_re.finditer(window):
                snap = carry.setdefault(dm.group(1), PlayerSnapshot(name=dm.group(1)))
                count = self._WORD_TO_INT.get(dm.group(2).lower(), 1)
                source = dm.group(3).strip()
                for _ in range(count):
                    snap.zones.hand.append("unknown")
                    events.append(
                        GameEvent(
                            turn_number=num,
                            verb="draw",
                            card_name=None,
                            player=dm.group(1),
                            source_card=source,
                        )
                    )

            # Graveyard moves + "graveyard" events
            for gm in graveyard_re.finditer(window):
                snap = carry.setdefault(gm.group(1), PlayerSnapshot(name=gm.group(1)))
                card = gm.group(2).strip()
                snap.zones.graveyard.append(card)
                # Remove from battlefield if present (best-effort)
                if card in snap.zones.battlefield:
                    snap.zones.battlefield.remove(card)
                events.append(
                    GameEvent(turn_number=num, verb="graveyard", card_name=card, player=gm.group(1))
                )

            # Exile moves + "exile" events
            for em in exile_re.finditer(window):
                snap = carry.setdefault(em.group(1), PlayerSnapshot(name=em.group(1)))
                card = em.group(2).strip()
                snap.zones.exile.append(card)
                # Remove from battlefield/graveyard if present (best-effort)
                if card in snap.zones.battlefield:
                    snap.zones.battlefield.remove(card)
                elif card in snap.zones.graveyard:
                    snap.zones.graveyard.remove(card)
                events.append(
                    GameEvent(turn_number=num, verb="exile", card_name=card, player=em.group(1))
                )

            # Life payments + "life_change" events
            for lm in life_pay_re.finditer(window):
                snap = carry.setdefault(lm.group(1), PlayerSnapshot(name=lm.group(1)))
                amt = int(lm.group(3))
                snap.life -= amt
                card = lm.group(2).strip()
                events.append(
                    GameEvent(
                        turn_number=num,
                        verb="life_change",
                        card_name=card,
                        player=lm.group(1),
                    )
                )

            snapshot_players = {
                name: PlayerSnapshot(
                    name=snap.name,
                    life=snap.life,
                    zones=PlayerZones(**snap.zones.model_dump()),
                    mana_pool=ManaPool(**snap.mana_pool.model_dump()),
                )
                for name, snap in carry.items()
            }
            turns.append(
                TurnSnapshot(
                    turn_number=num,
                    active_player=active,
                    players=snapshot_players,
                )
            )
        return turns, events


class MTGOTextLogStrategy(LogFormatStrategy):
    """Best-effort regex parser for MTGO plaintext logs."""

    _TEXT_HINTS = (
        b"wins the match",
        b"wins game",
        b"loses the match",
        b"--- Game",
        b"Format:",
        b"Turn ",
    )

    def can_parse(self, content: bytes, filename: str | None = None) -> bool:
        if not content:
            return False
        # Heuristic: looks like text and contains at least one MTGO marker.
        try:
            sample = content[: 64 * 1024].decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return False
        if not sample:
            return False
        lower = sample.encode("utf-8", errors="ignore").lower()
        return any(h.lower() in lower for h in self._TEXT_HINTS)

    def parse(self, content: bytes) -> ParsedMatch:
        text = content.decode("utf-8", errors="replace")

        match = ParsedMatch()

        if (m := _MATCH_ID_RE.search(text)) is not None:
            match.raw_match_id = m.group("id")
        if (m := _FORMAT_RE.search(text)) is not None:
            match.format = m.group("fmt").lower()
        if (m := _EVENT_RE.search(text)) is not None:
            match.event_type = m.group("evt").strip().lower()
        if (m := _PLAYERS_RE.search(text)) is not None:
            match.players = _split_players(m.group("players"))

        if (m := _MATCH_WIN_RE.search(text)) is not None:
            match.winner = _normalize_player(m.group("player"))
            if m.group("score"):
                match.match_result = re.sub(r"\s+", "", m.group("score"))
        elif (m := _MATCH_CONCEDE_RE.search(text)) is not None:
            conceder = _normalize_player(m.group("player"))
            match.winner = next((str(p) for p in match.players if str(p) != conceder), None)
        elif _MATCH_LOSE_RE.search(text):
            # Fallback: if we know who lost, opponent is winner — but we
            # only set match_result if we had a score.
            pass

        match.games = list(self._parse_games(text, match.players))

        # Fallback: if we never saw an explicit player list, harvest
        # whatever names showed up in turn/win/play markers.
        if not match.players:
            seen: dict[str, None] = {}
            for game in match.games:
                if game.winner:
                    seen.setdefault(game.winner, None)
                for turn in game.turns:
                    if turn.active_player:
                        seen.setdefault(turn.active_player, None)
                    for p in turn.players:
                        seen.setdefault(p, None)
            match.players = list(seen)

        # Synthesize "wins-losses" if we have per-game winners and know the
        # player set but the log never spelled out the score.
        if not match.match_result and match.games and match.winner and match.players:
            opp = next((p for p in match.players if p != match.winner), None)
            wins = sum(1 for g in match.games if g.winner == match.winner)
            losses = sum(1 for g in match.games if g.winner == opp) if opp else 0
            if wins:
                match.match_result = f"{wins}-{losses}"

        return match

    # --- game / turn extraction -----------------------------------------

    def _parse_games(self, text: str, players: list[str]) -> list[ParsedGame]:
        boundaries = [(m.start(), int(m.group("num"))) for m in _GAME_HEADER_RE.finditer(text)]
        if not boundaries:
            # No explicit game markers; treat the whole log as one game
            # if there's any per-game signal at all.
            game = self._parse_game_block(1, text, players)
            return [game] if (game.winner or game.turns) else []

        games: list[ParsedGame] = []
        for idx, (start, game_num) in enumerate(boundaries):
            end = boundaries[idx + 1][0] if idx + 1 < len(boundaries) else len(text)
            block = text[start:end]
            games.append(self._parse_game_block(game_num, block, players))
        return games

    def _parse_game_block(
        self,
        game_number: int,
        block: str,
        players: list[str],
    ) -> ParsedGame:
        game = ParsedGame(game_number=game_number)

        if (m := _GAME_WIN_RE.search(block)) is not None and int(m.group("num")) == game_number:
            game.winner = _normalize_player(m.group("player"))
            game.result = "win"
        if not game.result and (m := _GAME_RESULT_RE.search(block)) is not None:
            game.result = m.group("result").lower().rstrip("d")  # "conceded" -> "concede"

        game.turns, game.events = self._parse_turns(block, players)
        return game

    def _parse_turns(
        self, block: str, players: list[str]
    ) -> tuple[list[TurnSnapshot], list[GameEvent]]:
        turn_marks = [
            (m.start(), int(m.group("num")), m.group("player")) for m in _TURN_RE.finditer(block)
        ]
        if not turn_marks:
            return [], []

        # Carry forward state between turns: zones and life persist
        # turn-over-turn unless the log explicitly resets them.
        carry: dict[str, PlayerSnapshot] = {p: PlayerSnapshot(name=p) for p in players}

        turns: list[TurnSnapshot] = []
        all_events: list[GameEvent] = []
        for idx, (start, num, active) in enumerate(turn_marks):
            end = turn_marks[idx + 1][0] if idx + 1 < len(turn_marks) else len(block)
            window = block[start:end]
            snapshot, turn_events = self._snapshot_for_window(num, active, window, carry)
            turns.append(snapshot)
            all_events.extend(turn_events)
        return turns, all_events

    def _snapshot_for_window(
        self,
        turn_number: int,
        active_raw: str | None,
        window: str,
        carry: dict[str, PlayerSnapshot],
    ) -> tuple[TurnSnapshot, list[GameEvent]]:
        active = _normalize_player(active_raw) if active_raw else None
        events: list[GameEvent] = []

        # Life events have to be applied in document order so an explicit
        # "X's life: N" snapshot supersedes preceding deltas/damage rather
        # than getting clobbered by them. (Otherwise applying _DAMAGE_RE
        # after _LIFE_RE would double-count: log says "deals 3 damage" then
        # "Bob's life: 17" → snapshot shows 14 if damage runs last.)
        life_events: list[tuple[int, str]] = []
        for m in _LIFE_RE.finditer(window):
            life_events.append((m.start(), f"set:{m.group('player')}:{m.group('life')}"))
        for m in _LIFE_DELTA_RE.finditer(window):
            sign = "+" if m.group("verb").lower().startswith("gain") else "-"
            life_events.append((m.start(), f"delta:{m.group('player')}:{sign}{m.group('amt')}"))
        for m in _DAMAGE_RE.finditer(window):
            life_events.append((m.start(), f"dmg:{m.group('target')}:{m.group('amt')}"))
        life_events.sort(key=lambda e: e[0])
        for _, encoded in life_events:
            kind, who, value = encoded.split(":", 2)
            name = _normalize_player(who)
            if not name:
                continue
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            if kind == "set":
                snap.life = int(value)
            elif kind == "delta":
                snap.life += int(value)
                events.append(
                    GameEvent(
                        turn_number=turn_number,
                        verb="life_change",
                        card_name=None,
                        player=name,
                    )
                )
            elif kind == "dmg" and name in carry:
                carry[name].life -= int(value)
                events.append(
                    GameEvent(
                        turn_number=turn_number,
                        verb="damage",
                        card_name=None,
                        player=name,
                    )
                )

        # Zone movements.
        for play in _PLAY_RE.finditer(window):
            name = _normalize_player(play.group("player"))
            card = play.group("card").strip()
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            snap.zones.battlefield.append(card)
            # _PLAY_RE matches "plays", "casts", and "activates". Distinguish
            # the verb to emit the correct event type.
            verb_match = re.search(r"\b(plays|casts|activates)\b", play.group(0), re.IGNORECASE)
            verb_word = verb_match.group(1).lower() if verb_match else "play"
            if verb_word == "casts":
                event_verb = "cast"
            elif verb_word == "activates":
                event_verb = "cast"  # treat activations like casts for stats
            else:
                event_verb = "play"
            events.append(
                GameEvent(turn_number=turn_number, verb=event_verb, card_name=card, player=name)
            )

        for draw in _DRAW_RE.finditer(window):
            name = _normalize_player(draw.group("player"))
            card = draw.group("card")
            if card:
                snap = carry.setdefault(name, PlayerSnapshot(name=name))
                snap.zones.hand.append(card.strip())
            events.append(
                GameEvent(
                    turn_number=turn_number,
                    verb="draw",
                    card_name=card.strip() if card else None,
                    player=name,
                )
            )

        for disc in _DISCARD_RE.finditer(window):
            name = _normalize_player(disc.group("player"))
            card = disc.group("card").strip()
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            if card in snap.zones.hand:
                snap.zones.hand.remove(card)
            snap.zones.graveyard.append(card)
            events.append(
                GameEvent(turn_number=turn_number, verb="discard", card_name=card, player=name)
            )

        for move in _ZONE_MOVE_RE.finditer(window):
            name = _normalize_player(move.group("player"))
            zone = move.group("zone").lower()
            card = move.group("card").strip()
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            getattr(snap.zones, zone).append(card)
            # Map zone destination to event verb
            if zone == "exile":
                events.append(
                    GameEvent(turn_number=turn_number, verb="exile", card_name=card, player=name)
                )
            elif zone == "graveyard":
                events.append(
                    GameEvent(
                        turn_number=turn_number, verb="graveyard", card_name=card, player=name
                    )
                )

        # Mana pool.
        for mana in _MANA_FLOAT_RE.finditer(window):
            name = _normalize_player(mana.group("player"))
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            snap.mana_pool = _parse_mana_string(mana.group("pool"))
            events.append(
                GameEvent(turn_number=turn_number, verb="mana_float", card_name=None, player=name)
            )

        # Stack snapshot — at most one summary line per turn window.
        stack: list[StackEntry] = []
        for stk in _STACK_RE.finditer(window):
            contents = stk.group("contents").strip()
            if contents.lower() in ("empty", "(empty)", "-"):
                continue
            stack.append(StackEntry(description=contents))

        # Snapshot is a deep-ish copy of the carried state.
        snapshot_players: dict[str, PlayerSnapshot] = {
            name: PlayerSnapshot(
                name=snap.name,
                life=snap.life,
                zones=PlayerZones(**snap.zones.model_dump()),
                mana_pool=ManaPool(**snap.mana_pool.model_dump()),
            )
            for name, snap in carry.items()
        }

        return TurnSnapshot(
            turn_number=turn_number,
            active_player=active,
            players=snapshot_players,
            stack=stack,
        ), events


class LogParser:
    """Picks a strategy and runs it.

    Strategies are tried in order; the first one whose ``can_parse``
    returns True wins. If nothing claims the payload, an empty
    :class:`ParsedMatch` is returned — callers can decide how to
    handle that (typically: log a warning, skip persistence).
    """

    def __init__(self, strategies: list[LogFormatStrategy] | None = None) -> None:
        self._strategies: list[LogFormatStrategy] = strategies or [
            MTGODatStrategy(),
            MTGOTextLogStrategy(),
        ]

    def parse(self, content: bytes, filename: str | None = None) -> ParsedMatch:
        for strategy in self._strategies:
            if strategy.can_parse(content, filename):
                return strategy.parse(content)
        return ParsedMatch()
