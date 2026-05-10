"""MTGO log parser — strategy-pattern facade.

Two layers:

* :class:`LogFormatStrategy` — protocol/abstract. Implementations
  decide whether they can parse a given payload and produce a
  :class:`ParsedMatch`. Today: :class:`MTGOTextLogStrategy` (best-
  effort regex over MTGO's plaintext logs) plus a stubbed
  :class:`MTGODatStrategy` placeholder for the binary format that
  ships once it's reverse-engineered.
* :class:`LogParser` — orchestrator. Walks its strategy list, picks
  the first one that claims it can handle the payload, and runs it.

The text-log strategy is intentionally forgiving: MTGO's log format
varies and best-effort extraction is more useful than exceptions.
Missing data shows up as ``None`` / empty rather than parse failures.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from parser_service.parsing.models import (
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
    """Placeholder for the binary ``.dat`` format.

    Returns ``can_parse=False`` until the format is reverse-engineered.
    The slot exists so the orchestrator's strategy list is the single
    source of truth for "what can parser handle today".
    """

    def can_parse(self, content: bytes, filename: str | None = None) -> bool:
        return False

    def parse(self, content: bytes) -> ParsedMatch:
        raise NotImplementedError("MTGO .dat format support is not yet implemented")


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
            sample = content[:64 * 1024].decode("utf-8", errors="ignore")
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
        if (
            not match.match_result
            and match.games
            and match.winner
            and match.players
        ):
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

        if (m := _GAME_WIN_RE.search(block)) is not None and int(
            m.group("num")
        ) == game_number:
            game.winner = _normalize_player(m.group("player"))
            game.result = "win"
        if not game.result and (m := _GAME_RESULT_RE.search(block)) is not None:
            game.result = m.group("result").lower().rstrip("d")  # "conceded" -> "concede"

        game.turns = list(self._parse_turns(block, players))
        return game

    def _parse_turns(self, block: str, players: list[str]) -> list[TurnSnapshot]:
        turn_marks = [
            (m.start(), int(m.group("num")), m.group("player"))
            for m in _TURN_RE.finditer(block)
        ]
        if not turn_marks:
            return []

        # Carry forward state between turns: zones and life persist
        # turn-over-turn unless the log explicitly resets them.
        carry: dict[str, PlayerSnapshot] = {p: PlayerSnapshot(name=p) for p in players}

        turns: list[TurnSnapshot] = []
        for idx, (start, num, active) in enumerate(turn_marks):
            end = turn_marks[idx + 1][0] if idx + 1 < len(turn_marks) else len(block)
            window = block[start:end]
            snapshot = self._snapshot_for_window(num, active, window, carry)
            turns.append(snapshot)
        return turns

    def _snapshot_for_window(
        self,
        turn_number: int,
        active_raw: str | None,
        window: str,
        carry: dict[str, PlayerSnapshot],
    ) -> TurnSnapshot:
        active = _normalize_player(active_raw) if active_raw else None

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
            life_events.append(
                (m.start(), f"delta:{m.group('player')}:{sign}{m.group('amt')}")
            )
        for m in _DAMAGE_RE.finditer(window):
            life_events.append(
                (m.start(), f"dmg:{m.group('target')}:{m.group('amt')}")
            )
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
            elif kind == "dmg" and name in carry:
                carry[name].life -= int(value)

        # Zone movements.
        for play in _PLAY_RE.finditer(window):
            name = _normalize_player(play.group("player"))
            card = play.group("card").strip()
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            snap.zones.battlefield.append(card)

        for draw in _DRAW_RE.finditer(window):
            name = _normalize_player(draw.group("player"))
            card = draw.group("card")
            if card:
                snap = carry.setdefault(name, PlayerSnapshot(name=name))
                snap.zones.hand.append(card.strip())

        for disc in _DISCARD_RE.finditer(window):
            name = _normalize_player(disc.group("player"))
            card = disc.group("card").strip()
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            if card in snap.zones.hand:
                snap.zones.hand.remove(card)
            snap.zones.graveyard.append(card)

        for move in _ZONE_MOVE_RE.finditer(window):
            name = _normalize_player(move.group("player"))
            zone = move.group("zone").lower()
            card = move.group("card").strip()
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            getattr(snap.zones, zone).append(card)

        # Mana pool.
        for mana in _MANA_FLOAT_RE.finditer(window):
            name = _normalize_player(mana.group("player"))
            snap = carry.setdefault(name, PlayerSnapshot(name=name))
            snap.mana_pool = _parse_mana_string(mana.group("pool"))

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
        )


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
