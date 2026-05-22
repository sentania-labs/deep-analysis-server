"""Unit tests for the admin scraper-event-detail response shape.

Regression coverage for #72: the dashboard "Deck" column used to read
``deck_name`` only, which is always ``None`` for MTGO results (MTGO doesn't
publish archetype labels). The API now ships ``main_card_count`` and
``sideboard_card_count`` so the dashboard can show a meaningful "60 / 15"
fallback when the decklists exist but no archetype name does.
"""

from __future__ import annotations

from typing import Any

from analytics_service.main import _decklist_card_count


def test_decklist_card_count_sums_quantities() -> None:
    """Quantities are summed across all cards in the decklist."""
    decklist = {"Lightning Bolt": 4, "Goblin Guide": 4, "Lava Spike": 4}
    assert _decklist_card_count(decklist) == 12


def test_decklist_card_count_typical_mtgo_mainboard() -> None:
    """A standard 60-card mainboard sums to 60."""
    decklist = {
        "Mountain": 20,
        "Lightning Bolt": 4,
        "Goblin Guide": 4,
        "Lava Spike": 4,
        "Rift Bolt": 4,
        "Skewer the Critics": 4,
        "Searing Blaze": 4,
        "Boros Charm": 4,
        "Eidolon of the Great Revel": 4,
        "Monastery Swiftspear": 4,
        "Inspiring Vantage": 4,
    }
    assert _decklist_card_count(decklist) == 60


def test_decklist_card_count_handles_string_quantities() -> None:
    """JSONB sometimes round-trips quantities as strings; coerce them."""
    decklist = {"Lightning Bolt": "4", "Goblin Guide": "4"}
    assert _decklist_card_count(decklist) == 8


def test_decklist_card_count_skips_non_integer_values() -> None:
    """Garbage values are skipped, not fatal."""
    decklist: dict[str, Any] = {"Lightning Bolt": 4, "Bogus": None, "Other": "abc"}
    assert _decklist_card_count(decklist) == 4


def test_decklist_card_count_empty_dict() -> None:
    assert _decklist_card_count({}) == 0


def test_decklist_card_count_none() -> None:
    """``None`` decklists come back from the DB when the JSONB column is NULL."""
    assert _decklist_card_count(None) == 0


def test_decklist_card_count_non_dict() -> None:
    """Defensive: any unexpected shape returns 0 rather than raising."""
    assert _decklist_card_count("not a dict") == 0
    assert _decklist_card_count(42) == 0
    assert _decklist_card_count([("Lightning Bolt", 4)]) == 0
