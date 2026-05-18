"""Rule-based archetype classifier with ML fallback.

Pure-function implementation kept separate from the FastAPI route so
unit tests can exercise the algorithm against an in-memory list of
archetypes without standing up a database session.

The primary algorithm is overlap-fraction scoring against the admin-
managed archetype catalog. An ML classifier (TF-IDF + LogisticRegression
trained on mtgtop8 scraped data) is tried first when available — if it
returns a confident prediction, we use it; otherwise we fall back to the
rule-based scorer.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger("analytics.classifier")


class _ArchetypeLike(Protocol):
    """Structural type the classifier needs from an archetype.

    Both the SQLAlchemy ``Archetype`` model and the Pydantic
    ``ArchetypeRecord`` schema satisfy this — the route hands in
    whichever is convenient at the call site.
    """

    @property
    def id(self) -> object: ...

    @property
    def name(self) -> str: ...

    @property
    def format(self) -> str: ...

    @property
    def defining_cards(self) -> list[str]: ...


@dataclass
class ClassificationOutcome:
    """In-process result. The route layer maps this to the API shape."""

    archetype: _ArchetypeLike | None
    confidence: float
    source: str = "rule"  # "rule" or "ml"


@dataclass
class MLClassifyResult:
    """Lightweight result from the ML classifier path."""

    archetype_name: str | None
    confidence: float


def _norm(name: str) -> str:
    """Normalize for case- and whitespace-insensitive comparison."""
    return name.strip().casefold()


def classify_ml(card_names: list[str]) -> MLClassifyResult | None:
    """Try the ML classifier.  Returns None if model not loaded or unusable."""
    try:
        from analytics_service.ml_classifier import predict

        name, confidence = predict(card_names)
        if name is None:
            return None
        return MLClassifyResult(archetype_name=name, confidence=confidence)
    except Exception:  # noqa: BLE001
        _log.debug("ml classify failed; falling back to rule-based", exc_info=True)
        return None


def classify(
    card_names: Iterable[str],
    archetypes: Iterable[_ArchetypeLike],
    *,
    try_ml: bool = True,
) -> ClassificationOutcome:
    """Pick the archetype with the highest defining-card overlap.

    When ``try_ml`` is True (the default), the ML classifier is tried
    first. If it returns a confident prediction, the result is returned
    directly. Otherwise, the rule-based overlap scorer runs as before.

    Overlap is ``|defining ∩ played| / |defining|`` — the fraction of
    an archetype's defining cards that appeared in ``card_names``.
    Ties resolve to the archetype seen first in ``archetypes``.
    Returns a ``ClassificationOutcome`` with ``archetype=None`` and
    ``confidence=0.0`` if nothing scores above zero.
    """
    card_list = list(card_names) if not isinstance(card_names, list) else card_names
    played = {_norm(c) for c in card_list if c and c.strip()}
    if not played:
        return ClassificationOutcome(archetype=None, confidence=0.0)

    # --- ML path ---
    if try_ml:
        ml_result = classify_ml(card_list)
        if ml_result is not None and ml_result.archetype_name is not None:
            # Try to match the ML label back to a catalog archetype
            # so the caller gets the same shape as the rule-based path.
            archetypes_list = list(archetypes)
            ml_name_lower = ml_result.archetype_name.strip().casefold()
            for arch in archetypes_list:
                if arch.name.strip().casefold() == ml_name_lower:
                    return ClassificationOutcome(
                        archetype=arch,
                        confidence=ml_result.confidence,
                        source="ml",
                    )
            # ML predicted a label not in the catalog — still useful
            # for the classify endpoint but we can't return a catalog
            # archetype.  Fall through to rule-based.
            _log.debug(
                "ML predicted '%s' but no catalog match; falling back to rule-based",
                ml_result.archetype_name,
            )
            archetypes = archetypes_list  # avoid re-consuming the iterator

    # --- Rule-based path ---
    best: _ArchetypeLike | None = None
    best_score = 0.0
    for arch in archetypes:
        defining = [c for c in arch.defining_cards if c and c.strip()]
        if not defining:
            continue
        defining_normed = {_norm(c) for c in defining}
        overlap = len(defining_normed & played) / len(defining_normed)
        if overlap > best_score:
            best = arch
            best_score = overlap

    if best is None or best_score <= 0.0:
        return ClassificationOutcome(archetype=None, confidence=0.0)
    return ClassificationOutcome(archetype=best, confidence=best_score)
