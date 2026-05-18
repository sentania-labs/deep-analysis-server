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
    source: str = Field(description="'mtgtop8' or 'mtgo'")


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


class ScraperConfigListResponse(BaseModel):
    scrapers: list[ScraperConfigResponse]


class ScraperConfigUpdate(BaseModel):
    """Partial update for scraper configuration."""

    enabled: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=168)
