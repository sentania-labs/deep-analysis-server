"""Unit tests for the ML archetype classifier.

Tests the feature extraction, prediction fallback behaviour, and the
classify fallback chain (ML -> rule-based). Does not require a DB or
sklearn to be fully trained — uses mocks where needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

from analytics_service.classifier import classify
from analytics_service.ml_classifier import (
    _reset_state,
    card_names_to_text,
    decklist_to_card_names,
    predict,
)

# ---------------------------------------------------------------------------
# Feature extraction tests
# ---------------------------------------------------------------------------


class TestDecklistToCardNames:
    def test_dict_with_quantities(self) -> None:
        decklist: dict[str, int] = {"Lightning Bolt": 4, "Goblin Guide": 2}
        result = decklist_to_card_names(decklist)
        assert result.count("Lightning Bolt") == 4
        assert result.count("Goblin Guide") == 2

    def test_dict_with_string_quantities(self) -> None:
        decklist: dict[str, str] = {"Lightning Bolt": "4", "Goblin Guide": "2"}
        result = decklist_to_card_names(decklist)
        assert result.count("Lightning Bolt") == 4
        assert result.count("Goblin Guide") == 2

    def test_empty_dict(self) -> None:
        assert decklist_to_card_names({}) == []

    def test_none(self) -> None:
        assert decklist_to_card_names(None) == []

    def test_list_fallback(self) -> None:
        decklist: list[str] = ["Lightning Bolt", "Goblin Guide"]
        result = decklist_to_card_names(decklist)
        assert result == ["Lightning Bolt", "Goblin Guide"]

    def test_zero_quantity_treated_as_one(self) -> None:
        decklist: dict[str, int] = {"Lightning Bolt": 0}
        result = decklist_to_card_names(decklist)
        assert result == ["Lightning Bolt"]


class TestCardNamesToText:
    def test_joins_names(self) -> None:
        result = card_names_to_text(["Lightning Bolt", "Goblin Guide"])
        assert result == "Lightning Bolt Goblin Guide"

    def test_empty_list(self) -> None:
        assert card_names_to_text([]) == ""


# ---------------------------------------------------------------------------
# Predict tests (no model loaded)
# ---------------------------------------------------------------------------


class TestPredictNoModel:
    def setup_method(self) -> None:
        _reset_state()

    def test_returns_none_when_no_model(self) -> None:
        name, confidence = predict(["Lightning Bolt"])
        assert name is None
        assert confidence == 0.0

    def test_returns_none_for_empty_cards(self) -> None:
        name, confidence = predict([])
        assert name is None
        assert confidence == 0.0


# ---------------------------------------------------------------------------
# Classify fallback chain tests
# ---------------------------------------------------------------------------


@dataclass
class _FakeArchetype:
    id: int
    name: str
    format: str = "Modern"
    defining_cards: list[str] = field(default_factory=list)


class TestClassifyFallbackChain:
    """Test that classify() tries ML first, then falls back to rule-based."""

    def setup_method(self) -> None:
        _reset_state()

    def test_falls_back_to_rules_when_ml_not_loaded(self) -> None:
        burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt", "Goblin Guide"])
        out = classify(["Lightning Bolt", "Goblin Guide"], [burn])
        assert out.archetype is burn
        assert out.confidence == 1.0
        assert out.source == "rule"

    def test_uses_ml_when_available_and_confident(self) -> None:
        burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt"])
        tron = _FakeArchetype(2, "Tron", defining_cards=["Urza's Tower"])

        with patch(
            "analytics_service.classifier.classify_ml",
            return_value=type("MLResult", (), {"archetype_name": "Tron", "confidence": 0.95})(),
        ):
            out = classify(["Lightning Bolt"], [burn, tron])
        assert out.archetype is tron
        assert out.confidence == 0.95
        assert out.source == "ml"

    def test_falls_back_when_ml_label_not_in_catalog(self) -> None:
        burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt"])

        with patch(
            "analytics_service.classifier.classify_ml",
            return_value=type(
                "MLResult", (), {"archetype_name": "Unknown Deck", "confidence": 0.9}
            )(),
        ):
            out = classify(["Lightning Bolt"], [burn])
        # ML label not in catalog, should fall back to rule-based.
        assert out.archetype is burn
        assert out.confidence == 1.0
        assert out.source == "rule"

    def test_skips_ml_when_try_ml_false(self) -> None:
        burn = _FakeArchetype(1, "Burn", defining_cards=["Lightning Bolt"])
        out = classify(["Lightning Bolt"], [burn], try_ml=False)
        assert out.archetype is burn
        assert out.source == "rule"


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------


class TestCanonicalArchetypeSchemas:
    def test_create_schema_validates(self) -> None:
        from analytics_service.schemas import CanonicalArchetypeCreate

        obj = CanonicalArchetypeCreate(
            canonical_name="Energy",
            format="Legacy",
            variant_tags=["Boros", "4c"],
        )
        assert obj.canonical_name == "Energy"
        assert obj.format == "Legacy"
        assert obj.variant_tags == ["Boros", "4c"]

    def test_create_schema_rejects_empty_name(self) -> None:
        import pytest
        from analytics_service.schemas import CanonicalArchetypeCreate
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CanonicalArchetypeCreate(canonical_name="", format="Legacy")

    def test_label_mapping_create(self) -> None:
        import uuid

        from analytics_service.schemas import ArchetypeLabelMappingCreate

        obj = ArchetypeLabelMappingCreate(
            scraped_label="Boros Energy",
            canonical_id=uuid.uuid4(),
        )
        assert obj.scraped_label == "Boros Energy"

    def test_classifier_status(self) -> None:
        from analytics_service.schemas import ClassifierStatus

        s = ClassifierStatus(loaded=True, sample_count=100, label_count=10)
        assert s.loaded is True
        assert s.sample_count == 100

    def test_train_result(self) -> None:
        from analytics_service.schemas import TrainResult

        r = TrainResult(sample_count=500, label_count=20, accuracy=0.85, message="ok")
        assert r.accuracy == 0.85
