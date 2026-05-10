"""MTGO log parsing — public API.

The :class:`LogParser` orchestrator picks the right
:class:`LogFormatStrategy` for a given payload and returns a
:class:`ParsedMatch`. The text-log strategy is the only one shipped
today; a binary ``.dat`` strategy will be slotted in here once the
format is reverse-engineered.
"""

from parser_service.parsing.models import (
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
