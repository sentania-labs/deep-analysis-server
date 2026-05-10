"""Pydantic models that describe the parser's output shape.

These models are persistence-agnostic; they capture what the log
parser can extract from a single MTGO match log. The Redis consumer
and SQLAlchemy layer translate them into rows in ``parser.matches``,
``parser.games``, and ``parser.game_states``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PlayerZones(BaseModel):
    """Best-effort zone snapshot for a single player at a point in time.

    Each zone is a list of card names. The text log format reveals
    individual cards as they enter or leave a zone — so any zone is
    "what we know to be there", not necessarily the full ground truth.
    """

    battlefield: list[str] = Field(default_factory=list)
    hand: list[str] = Field(default_factory=list)
    library: list[str] = Field(default_factory=list)
    graveyard: list[str] = Field(default_factory=list)
    exile: list[str] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)


class ManaPool(BaseModel):
    """Floating mana, by color symbol. Empty pool is the default."""

    W: int = 0
    U: int = 0
    B: int = 0
    R: int = 0
    G: int = 0
    C: int = 0  # generic / colorless


class PlayerSnapshot(BaseModel):
    name: str
    life: int = 20
    zones: PlayerZones = Field(default_factory=PlayerZones)
    mana_pool: ManaPool = Field(default_factory=ManaPool)


class StackEntry(BaseModel):
    """A single object on the stack — a spell or an activated/triggered ability."""

    source_player: str | None = None
    kind: Literal["spell", "ability", "trigger", "unknown"] = "unknown"
    description: str = ""
    targets: list[str] = Field(default_factory=list)


class TurnSnapshot(BaseModel):
    turn_number: int
    active_player: str | None = None
    players: dict[str, PlayerSnapshot] = Field(default_factory=dict)
    stack: list[StackEntry] = Field(default_factory=list)


class ParsedGame(BaseModel):
    game_number: int
    winner: str | None = None
    result: str | None = None  # "win", "loss", "draw", "concede"
    turns: list[TurnSnapshot] = Field(default_factory=list)


class ParsedMatch(BaseModel):
    """Top-level result of parsing a single MTGO match log."""

    raw_match_id: str | None = None
    format: str | None = None
    event_type: str | None = None
    players: list[str] = Field(default_factory=list)
    match_result: str | None = None  # "2-0", "2-1", etc.
    winner: str | None = None
    games: list[ParsedGame] = Field(default_factory=list)

    @property
    def game_count(self) -> int:
        return len(self.games)
