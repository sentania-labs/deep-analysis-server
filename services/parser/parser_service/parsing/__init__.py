"""MTGO log parsing — public API.

The :class:`LogParser` orchestrator picks the right
:class:`LogFormatStrategy` for a given payload and returns a
:class:`ParsedMatch`. Today both the binary ``.dat`` and plaintext
log formats are supported via :class:`MTGODatStrategy` and
:class:`MTGOTextLogStrategy` respectively.
"""

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
from parser_service.parsing.parser import (
    LogFormatStrategy,
    LogParser,
    MTGODatStrategy,
    MTGOTextLogStrategy,
)

__all__ = [
    "GameEvent",
    "LogFormatStrategy",
    "LogParser",
    "MTGODatStrategy",
    "MTGOTextLogStrategy",
    "ManaPool",
    "ParsedGame",
    "ParsedMatch",
    "PlayerSnapshot",
    "PlayerZones",
    "StackEntry",
    "TurnSnapshot",
]
