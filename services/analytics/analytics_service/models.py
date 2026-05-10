"""SQLAlchemy models for the analytics service.

The archetype catalog (``analytics.archetypes``) is the only table the
analytics service owns. Everything else analytics queries lives in
other schemas (``parser.matches``, ``parser.games``, ``parser.game_states``,
``ingest.user_uploads``, ``auth.users``); analytics holds no models for
those, only ad-hoc SELECTs.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

metadata = MetaData(schema="analytics")


class Base(DeclarativeBase):
    metadata = metadata


class Archetype(Base):
    __tablename__ = "archetypes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(Text, nullable=False)
    defining_cards: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default="[]")
    sample_decklists: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
