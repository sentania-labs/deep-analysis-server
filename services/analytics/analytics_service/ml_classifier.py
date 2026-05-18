"""ML archetype classifier backed by TF-IDF + LogisticRegression.

Training data comes from ``analytics.mtgtop8_results`` joined with the
optional ``analytics.archetype_label_mappings`` → ``canonical_archetypes``
taxonomy.  Where no mapping exists, the raw ``deck_name`` from mtgtop8 is
used as the label — admin can refine later by adding canonical mappings.

The model is persisted as a pickle file (configurable path, default
``/data/ml_model.pkl``) so it survives service restarts without
retraining.  ``predict()`` is synchronous — the sklearn inference is fast
enough for inline use in the classify endpoint.
"""

from __future__ import annotations

import logging
import os
import pickle
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_log = logging.getLogger("analytics.ml_classifier")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODEL_PATH = Path(os.environ.get("DA_ML_MODEL_PATH", "/data/ml_model.pkl"))
CONFIDENCE_THRESHOLD = 0.3

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------


@dataclass
class _ModelState:
    """Mutable singleton holding the trained model artefacts."""

    pipeline: Any = None  # sklearn Pipeline (vectorizer + classifier)
    label_names: list[str] = field(default_factory=list)
    loaded: bool = False
    sample_count: int = 0
    label_count: int = 0
    last_trained_at: datetime | None = None


_state = _ModelState()
_lock = threading.Lock()


def _reset_state() -> None:
    """Test hook — clear module state."""
    global _state
    _state = _ModelState()


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------


def decklist_to_card_names(decklist: dict[str, Any] | list[Any] | None) -> list[str]:
    """Flatten a decklist JSONB blob into a bag-of-card-names string list.

    The mtgtop8 scraper stores decklists as ``{"Card Name": qty, ...}``
    dicts.  We repeat each card name ``qty`` times so TF-IDF captures
    frequency differences (e.g. 4x Lightning Bolt vs 1x).
    """
    if decklist is None:
        return []
    if isinstance(decklist, dict):
        names: list[str] = []
        for card, qty in decklist.items():
            count = int(qty) if isinstance(qty, (int, float, str)) else 1
            names.extend([card] * max(count, 1))
        return names
    # If it's a list (unlikely but defensive), just flatten strings.
    return [str(item) for item in decklist if item]


def card_names_to_text(card_names: list[str]) -> str:
    """Join card names into a single string for TF-IDF vectorization."""
    return " ".join(card_names)


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------


def predict(card_names: list[str]) -> tuple[str | None, float]:
    """Return ``(canonical_name, confidence)`` for the given card list.

    Returns ``(None, 0.0)`` when the model is not loaded or confidence
    falls below the threshold.
    """
    if not _state.loaded or _state.pipeline is None:
        return None, 0.0
    if not card_names:
        return None, 0.0

    doc = card_names_to_text(card_names)
    try:
        proba = _state.pipeline.predict_proba([doc])[0]
        best_idx = int(proba.argmax())
        confidence = float(proba[best_idx])
        if confidence < CONFIDENCE_THRESHOLD:
            return None, confidence
        label = _state.label_names[best_idx]
        return label, confidence
    except Exception:  # noqa: BLE001
        _log.exception("ml predict failed")
        return None, 0.0


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


@dataclass
class TrainResult:
    sample_count: int = 0
    label_count: int = 0
    accuracy: float = 0.0
    message: str = ""


async def retrain(session: AsyncSession) -> TrainResult:
    """Pull training data from the DB, fit a new model, and persist it.

    Training data is ``(decklist_main, label)`` pairs where ``label`` is
    the canonical name (if a mapping exists) or the raw ``deck_name``.
    """
    # 1. Pull training data — LEFT JOIN to get canonical labels where available.
    rows = (
        await session.execute(
            text(
                """
                SELECT r.decklist_main, r.deck_name,
                       ca.canonical_name
                FROM analytics.mtgtop8_results r
                LEFT JOIN analytics.archetype_label_mappings alm
                    ON alm.scraped_label = r.deck_name
                LEFT JOIN analytics.canonical_archetypes ca
                    ON ca.id = alm.canonical_id
                WHERE r.deck_name IS NOT NULL
                  AND r.deck_name != ''
                  AND r.decklist_main IS NOT NULL
                """
            )
        )
    ).all()

    if not rows:
        return TrainResult(message="no training data found")

    docs: list[str] = []
    labels: list[str] = []
    for decklist_main, deck_name, canonical_name in rows:
        card_names = decklist_to_card_names(decklist_main)
        if not card_names:
            continue
        docs.append(card_names_to_text(card_names))
        # Prefer canonical name, fall back to raw deck_name.
        labels.append(canonical_name if canonical_name else deck_name)

    if len(docs) < 2:
        return TrainResult(
            sample_count=len(docs),
            label_count=len(set(labels)),
            message="not enough training samples (need at least 2)",
        )

    unique_labels = sorted(set(labels))
    if len(unique_labels) < 2:
        return TrainResult(
            sample_count=len(docs),
            label_count=len(unique_labels),
            message="not enough distinct labels (need at least 2)",
        )

    # 2. Build pipeline and fit.
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
        from sklearn.pipeline import Pipeline
    except ImportError:
        return TrainResult(message="scikit-learn not installed")

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=1000, solver="lbfgs", multi_class="auto")),
        ]
    )

    pipeline.fit(docs, labels)

    # 3. Evaluate with cross-validation if enough samples.
    accuracy = 0.0
    if len(docs) >= 5:
        n_splits = min(5, len(unique_labels), len(docs))
        if n_splits >= 2:
            try:
                scores = cross_val_score(pipeline, docs, labels, cv=n_splits, scoring="accuracy")
                accuracy = float(scores.mean())
            except Exception:  # noqa: BLE001
                _log.warning("cross-validation failed; reporting accuracy=0", exc_info=True)

    # 4. Persist model to disk.
    now = datetime.now(UTC)
    try:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(
                {
                    "pipeline": pipeline,
                    "label_names": unique_labels,
                    "sample_count": len(docs),
                    "label_count": len(unique_labels),
                    "trained_at": now.isoformat(),
                },
                f,
            )
        _log.info(
            "saved ML model to %s (%d samples, %d labels)",
            MODEL_PATH, len(docs), len(unique_labels),
        )
    except Exception:  # noqa: BLE001
        _log.warning(
            "could not persist model to %s; model is in-memory only",
            MODEL_PATH, exc_info=True,
        )

    # 5. Update in-memory state.
    with _lock:
        _state.pipeline = pipeline
        _state.label_names = unique_labels
        _state.loaded = True
        _state.sample_count = len(docs)
        _state.label_count = len(unique_labels)
        _state.last_trained_at = now

    return TrainResult(
        sample_count=len(docs),
        label_count=len(unique_labels),
        accuracy=accuracy,
        message="model trained successfully",
    )


# ---------------------------------------------------------------------------
# Model loading (startup / lazy)
# ---------------------------------------------------------------------------


def load_model() -> bool:
    """Try to load a persisted model from disk.  Returns True on success."""
    if not MODEL_PATH.exists():
        _log.info("no persisted ML model at %s", MODEL_PATH)
        return False
    try:
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)  # noqa: S301
        with _lock:
            _state.pipeline = data["pipeline"]
            _state.label_names = data["label_names"]
            _state.sample_count = data.get("sample_count", 0)
            _state.label_count = data.get("label_count", 0)
            trained_at = data.get("trained_at")
            if trained_at:
                _state.last_trained_at = datetime.fromisoformat(trained_at)
            _state.loaded = True
        _log.info(
            "loaded ML model from %s (%d samples, %d labels)",
            MODEL_PATH,
            _state.sample_count,
            _state.label_count,
        )
        return True
    except Exception:  # noqa: BLE001
        _log.exception("failed to load ML model from %s", MODEL_PATH)
        return False


def get_status() -> dict[str, Any]:
    """Return current model status as a plain dict."""
    return {
        "loaded": _state.loaded,
        "sample_count": _state.sample_count,
        "label_count": _state.label_count,
        "last_trained_at": _state.last_trained_at,
    }
