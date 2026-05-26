"""SQLAlchemy models for the analytics service.

The archetype catalog (``analytics.archetypes``) is the only table the
analytics service owns outside the ML classifier taxonomy. Everything
else analytics queries lives in other schemas (``parser.matches``,
``parser.games``, ``parser.game_states``, ``ingest.user_uploads``,
``auth.users``); analytics holds no models for those, only ad-hoc SELECTs.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Date,
    DateTime,
    ForeignKey,
    MetaData,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

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


class CanonicalArchetype(Base):
    __tablename__ = "canonical_archetypes"
    __table_args__ = (
        UniqueConstraint("canonical_name", "format", name="canonical_archetypes_name_format_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    canonical_name: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(Text, nullable=False)
    variant_tags: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    label_mappings: Mapped[list[ArchetypeLabelMapping]] = relationship(
        back_populates="canonical_archetype",
        cascade="all, delete-orphan",
    )


class ArchetypeLabelMapping(Base):
    __tablename__ = "archetype_label_mappings"
    __table_args__ = (
        UniqueConstraint(
            "scraped_label", "canonical_id", name="archetype_label_mappings_label_canonical_key"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scraped_label: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    canonical_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analytics.canonical_archetypes.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    canonical_archetype: Mapped[CanonicalArchetype] = relationship(
        back_populates="label_mappings",
    )


class BnrEvent(Base):
    __tablename__ = "bnr_events"
    __table_args__ = (
        UniqueConstraint("format", "effective_date", name="bnr_events_format_effective_date_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    format: Mapped[str] = mapped_column(Text, nullable=False)
    effective_date: Mapped[date] = mapped_column(Date, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    card_actions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
