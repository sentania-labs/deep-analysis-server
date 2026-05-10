"""Unit tests for the rule-based archetype classifier.

Exercises :func:`analytics_service.classifier.classify` against an
in-memory list of archetypes — no DB or HTTP — so it stays fast and
self-contained.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from analytics_service.classifier import classify


@dataclass
class _FakeArchetype:
    """Stand-in for the SQLAlchemy ``Archetype`` row.

    The classifier only reads ``id``, ``name``, ``format``, and
    ``defining_cards`` — anything that satisfies the structural
    protocol works.
    """

    id: int
    name: str
    format: str = "Modern"
    defining_cards: list[str] = field(default_factory=list)


def test_returns_none_when_card_names_empty() -> None:
    archs = [_FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt"])]
    out = classify([], archs)
    assert out.archetype is None
    assert out.confidence == 0.0


def test_returns_none_when_archetypes_empty() -> None:
    out = classify(["Lightning Bolt"], [])
    assert out.archetype is None
    assert out.confidence == 0.0


def test_returns_none_when_no_overlap() -> None:
    archs = [
        _FakeArchetype(
            1,
            "Burn",
            defining_cards=["Lightning Bolt", "Goblin Guide"],
        ),
    ]
    out = classify(["Counterspell", "Brainstorm"], archs)
    assert out.archetype is None
    assert out.confidence == 0.0


def test_picks_archetype_with_highest_overlap_ratio() -> None:
    burn = _FakeArchetype(
        1,
        "Burn",
        defining_cards=["Lightning Bolt", "Goblin Guide", "Lava Spike"],
    )
    tron = _FakeArchetype(
        2,
        "Tron",
        defining_cards=["Urza's Tower", "Urza's Mine", "Karn Liberated"],
    )

    out = classify(["Lightning Bolt", "Goblin Guide"], [burn, tron])
    assert out.archetype is burn
    # 2 of 3 burn defining cards present.
    assert out.confidence == 2 / 3


def test_full_overlap_yields_confidence_one() -> None:
    burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt", "Lava Spike"])
    out = classify(["Lightning Bolt", "Lava Spike", "Mountain"], [burn])
    assert out.archetype is burn
    assert out.confidence == 1.0


def test_match_is_case_insensitive_and_trimmed() -> None:
    burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt", "Goblin Guide"])
    out = classify(["  lightning bolt  ", "GOBLIN GUIDE"], [burn])
    assert out.archetype is burn
    assert out.confidence == 1.0


def test_blank_card_names_are_ignored() -> None:
    burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt", "Goblin Guide"])
    out = classify(["", "   ", "Lightning Bolt"], [burn])
    assert out.archetype is burn
    assert out.confidence == 0.5


def test_archetype_with_empty_defining_cards_is_skipped() -> None:
    empty = _FakeArchetype(1, "EmptyCatalogEntry", defining_cards=[])
    burn = _FakeArchetype(2, "Burn", defining_cards=["Lightning Bolt"])
    out = classify(["Lightning Bolt"], [empty, burn])
    assert out.archetype is burn
    assert out.confidence == 1.0


def test_tie_resolves_to_first_seen() -> None:
    a = _FakeArchetype(1, "A", defining_cards=["Card X"])
    b = _FakeArchetype(2, "B", defining_cards=["Card X"])
    out = classify(["Card X"], [a, b])
    # Both score 1.0; first iteration wins.
    assert out.archetype is a


def test_confidence_is_float_in_unit_interval() -> None:
    archs = [
        _FakeArchetype(
            1,
            "Burn",
            defining_cards=[
                "Lightning Bolt",
                "Goblin Guide",
                "Lava Spike",
                "Eidolon of the Great Revel",
            ],
        ),
    ]
    out = classify(["Lightning Bolt"], archs)
    assert isinstance(out.confidence, float)
    assert 0.0 <= out.confidence <= 1.0
    assert out.confidence == 0.25
