"""Pydantic schemas for the analytics service."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ArchetypeRecord(BaseModel):
    """A single row from ``analytics.archetypes``."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    format: str
    defining_cards: list[str] = Field(default_factory=list)
    sample_decklists: list[Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ArchetypeListView(BaseModel):
    archetypes: list[ArchetypeRecord]
    total: int


class ArchetypeWriteRequest(BaseModel):
    """Body for create + update — admin-only routes."""

    name: str = Field(..., min_length=1, max_length=200)
    format: str = Field(..., min_length=1, max_length=64)
    defining_cards: list[str] = Field(default_factory=list)
    sample_decklists: list[Any] | None = None


class ClassifyRequest(BaseModel):
    card_names: list[str] = Field(default_factory=list)


class ClassifyResult(BaseModel):
    """Best-matching archetype and its overlap-based confidence.

    ``archetype_id`` and ``archetype_name`` / ``format`` are null when
    the catalog is empty, when the request carries no card names, or
    when no defining-card overlap exists with any catalog entry.
    ``confidence`` is the share of an archetype's defining cards that
    appeared in the request — a float in [0.0, 1.0].
    """

    archetype_id: uuid.UUID | None = None
    archetype_name: str | None = None
    format: str | None = None
    confidence: float = 0.0


# ---------------------------------------------------------------------------
# Metagame API schemas (F10)
# ---------------------------------------------------------------------------


class MetagameFormat(BaseModel):
    """A format with aggregated event counts from scraped data."""

    format: str
    event_count: int
    latest_event_date: date | None = None


class MetagameFormatList(BaseModel):
    formats: list[MetagameFormat]


class ArchetypeTier(BaseModel):
    """Archetype popularity and performance within a format."""

    deck_name: str
    popularity_pct: float = Field(description="Percentage of total results")
    avg_placement: float | None = None
    sample_count: int = 0


class MetagameTierList(BaseModel):
    format: str
    window: str
    tiers: list[ArchetypeTier]
    total_results: int = 0


class MetagameEvent(BaseModel):
    """Summary of a single event from scraped data."""

    event_id: int
    event_name: str
    event_date: date | None = None
    player_count: int | None = None
    source: str = Field(description="primary source — 'mtgtop8' or 'mtgo'")
    sources: list[str] = Field(
        default_factory=list,
        description=(
            "All scraper feeds that contributed to this canonical event, "
            "primary first. E.g. ['mtgtop8', 'mtgo'] when the same event "
            "appears in both."
        ),
    )


class MetagameEventList(BaseModel):
    events: list[MetagameEvent]
    total: int
    page: int
    per_page: int


class EventResultEntry(BaseModel):
    """A single player result within an event."""

    player_name: str
    placement: int | None = None
    deck_name: str | None = None
    decklist_main: Any = Field(default_factory=dict)
    decklist_sideboard: Any = Field(default_factory=dict)


class EventDetail(BaseModel):
    """Full event with all player results."""

    event_id: int
    event_name: str
    event_date: date | None = None
    player_count: int | None = None
    source: str
    sources: list[str] = Field(
        default_factory=list,
        description=(
            "All scraper feeds that contributed to this event view, "
            "primary first. When more than one feed contributed, the "
            "participant list is a union across feeds."
        ),
    )
    results: list[EventResultEntry] = Field(default_factory=list)


class TrendDataset(BaseModel):
    """A single archetype's popularity over time."""

    label: str
    data: list[float]


class MetagameTrends(BaseModel):
    """Time-series archetype popularity data for charting."""

    format: str
    window: str
    labels: list[str] = Field(default_factory=list)
    datasets: list[TrendDataset] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scraper Admin API schemas (F12)
# ---------------------------------------------------------------------------


class ScraperConfigResponse(BaseModel):
    """Merged scraper config + health for admin display."""

    scraper_name: str
    enabled: bool = True
    interval_hours: int = 24
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    consecutive_failures: int = 0
    is_broken: bool = False
    last_error: str | None = None
    #: Live-run state (#127). ``running_since`` is the start of the run
    #: currently holding the scraper's lock; both clear when it ends.
    is_running: bool = False
    running_since: datetime | None = None
    run_trigger: str | None = None


class ScraperConfigListResponse(BaseModel):
    scrapers: list[ScraperConfigResponse]


class ScraperConfigUpdate(BaseModel):
    """Partial update for scraper configuration."""

    enabled: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=168)


# ---------------------------------------------------------------------------
# ML Classifier schemas (F9)
# ---------------------------------------------------------------------------


class CanonicalArchetypeRecord(BaseModel):
    """A single row from ``analytics.canonical_archetypes``."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canonical_name: str
    format: str
    variant_tags: list[str] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CanonicalArchetypeCreate(BaseModel):
    """Body for creating a canonical archetype."""

    canonical_name: str = Field(..., min_length=1, max_length=200)
    format: str = Field(..., min_length=1, max_length=64)
    variant_tags: list[str] | None = None


class CanonicalArchetypeListView(BaseModel):
    archetypes: list[CanonicalArchetypeRecord]
    total: int


class ArchetypeLabelMappingRecord(BaseModel):
    """A single row from ``analytics.archetype_label_mappings``."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scraped_label: str
    canonical_id: uuid.UUID
    canonical_name: str | None = None
    created_at: datetime | None = None


class ArchetypeLabelMappingCreate(BaseModel):
    """Body for creating a label mapping."""

    scraped_label: str = Field(..., min_length=1, max_length=500)
    canonical_id: uuid.UUID


class ArchetypeLabelMappingListView(BaseModel):
    mappings: list[ArchetypeLabelMappingRecord]
    total: int


class ClassifierStatus(BaseModel):
    """Status of the ML classifier model."""

    loaded: bool = False
    sample_count: int = 0
    label_count: int = 0
    last_trained_at: datetime | None = None


class TrainResult(BaseModel):
    """Result of a model training run."""

    sample_count: int = 0
    label_count: int = 0
    accuracy: float = 0.0
    message: str = ""


# ---------------------------------------------------------------------------
# B&R Events schemas
# ---------------------------------------------------------------------------


class CardAction(BaseModel):
    card: str = Field(..., min_length=1)
    action: str = Field(..., pattern="^(banned|unbanned|restricted|unrestricted|suspended)$")


class BnrEventRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    format: str
    effective_date: date
    description: str
    card_actions: list[CardAction] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class BnrEventListView(BaseModel):
    events: list[BnrEventRecord]
    total: int


class BnrEventWriteRequest(BaseModel):
    format: str = Field(..., min_length=1, max_length=64)
    effective_date: date
    description: str = Field(..., min_length=1, max_length=500)
    card_actions: list[CardAction] = Field(default_factory=list)


class WikiImportResult(BaseModel):
    imported: int = 0
    skipped: int = 0
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Admin match schemas
# ---------------------------------------------------------------------------

_ADMIN_MATCHES_DEFAULT_PER_PAGE = 20


class AdminMatchItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    match_id: str
    user_id: int
    user_email: str | None = None
    format_: str | None = Field(default=None, alias="format")
    players: list[str] = Field(default_factory=list)
    match_result: str | None = None
    winner: str | None = None
    game_count: int = 0
    played_at: datetime | None = None
    # True only when both players have equal nonzero game-win counts —
    # mirrors analytics.list_matches / _classify_match. A null winner
    # with no resolved game winners is "incomplete", not a draw.
    is_draw: bool = False
    # Holding-pen state — see alembic 025. ``None`` is normal /
    # user-visible, ``'pending_review'`` is awaiting an admin verdict,
    # ``'rejected'`` is admin-discarded. Admin endpoints surface all
    # three; user-facing endpoints only return None rows.
    review_status: str | None = None


class AdminMatchListResponse(BaseModel):
    matches: list[AdminMatchItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = _ADMIN_MATCHES_DEFAULT_PER_PAGE


class MatchReviewRequest(BaseModel):
    review_status: str | None = None
