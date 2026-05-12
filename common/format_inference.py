"""Infer match format from the card pool.

Cross-references card names from a parsed match against
``catalog.cards.legalities`` to find the narrowest format where every
card is legal. Basic lands are excluded since they're legal everywhere
and don't help discriminate.

The inference is best-effort: if no cards are found in the catalog
(pre-sync, or all tokens/emblems), returns None.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    from parser_service.parsing.models import ParsedMatch

_log = logging.getLogger("analytics.format_inference")

_FORMAT_HIERARCHY: list[str] = [
    "standard",
    "pioneer",
    "modern",
    "legacy",
    "vintage",
]

_BASIC_LANDS = frozenset({
    "Plains", "Island", "Swamp", "Mountain", "Forest",
    "Snow-Covered Plains", "Snow-Covered Island", "Snow-Covered Swamp",
    "Snow-Covered Mountain", "Snow-Covered Forest",
    "Wastes",
})

_LEGALITIES_SQL = text(
    """
    SELECT DISTINCT ON (name) name, legalities
      FROM catalog.cards
     WHERE name = ANY(:names)
       AND legalities IS NOT NULL
     ORDER BY name, synced_at DESC
    """
)


def collect_card_names(parsed: ParsedMatch) -> list[str]:
    """Extract unique card names from all games in a parsed match."""
    names: set[str] = set()
    for game in parsed.games:
        for turn in game.turns:
            for snap in turn.players.values():
                names.update(snap.zones.battlefield)
    return sorted(names)


def infer_format_from_cards(
    card_legalities: dict[str, dict[str, str]],
) -> str | None:
    """Pure function: given {card_name: {format: status}}, return the
    narrowest format where every card is legal or restricted.

    Returns None if no cards have legality data.
    """
    if not card_legalities:
        return None

    for fmt in _FORMAT_HIERARCHY:
        all_legal = True
        for _card, legs in card_legalities.items():
            status = legs.get(fmt)
            if status not in ("legal", "restricted"):
                all_legal = False
                break
        if all_legal:
            return fmt

    return None


async def infer_format_for_match(
    session: AsyncSession,
    card_names: list[str],
) -> str | None:
    """Look up legalities from catalog.cards and infer format."""
    filtered = [n for n in card_names if n not in _BASIC_LANDS]
    if not filtered:
        return None

    rows = (
        await session.execute(_LEGALITIES_SQL, {"names": filtered})
    ).mappings().all()

    if not rows:
        _log.debug(
            "format inference: no catalog matches",
            extra={"card_count": len(filtered)},
        )
        return None

    card_legalities: dict[str, dict[str, str]] = {}
    for row in rows:
        legs = row["legalities"]
        if isinstance(legs, dict):
            card_legalities[row["name"]] = legs

    result = infer_format_from_cards(card_legalities)
    if result:
        result = result.title()
        _log.info(
            "format inferred",
            extra={"format": result, "cards_checked": len(card_legalities)},
        )
    return result
