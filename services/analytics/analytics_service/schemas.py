"""Pydantic schemas for the analytics service."""

from __future__ import annotations

import uuid
from datetime import datetime
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
