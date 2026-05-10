"""Rule-based archetype classifier.

Pure-function implementation kept separate from the FastAPI route so
unit tests can exercise the algorithm against an in-memory list of
archetypes without standing up a database session. The algorithm is
intentionally simple — overlap fraction of defining cards — and is
expected to be replaced by a richer scorer in a later milestone.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol


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


def _norm(name: str) -> str:
    """Normalize for case- and whitespace-insensitive comparison."""
    return name.strip().casefold()


def classify(
    card_names: Iterable[str],
    archetypes: Iterable[_ArchetypeLike],
) -> ClassificationOutcome:
    """Pick the archetype with the highest defining-card overlap.

    Overlap is ``|defining ∩ played| / |defining|`` — the fraction of
    an archetype's defining cards that appeared in ``card_names``.
    Ties resolve to the archetype seen first in ``archetypes``.
    Returns a ``ClassificationOutcome`` with ``archetype=None`` and
    ``confidence=0.0`` if nothing scores above zero.
    """
    played = {_norm(c) for c in card_names if c and c.strip()}
    if not played:
        return ClassificationOutcome(archetype=None, confidence=0.0)

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
