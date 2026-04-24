"""SQLAlchemy models for the ingest service.

Two tables in the ``ingest`` schema:

- ``game_log_files`` — content-addressed (sha256 PK). Device- and
  user-neutral. Row count tracks distinct file contents in the system.
- ``user_uploads`` — per-user attribution. One row per successful
  upload event, even when the underlying content is deduped. Points to
  a ``game_log_files`` row + to ``auth.users`` and
  ``auth.agent_registrations``.

Cross-schema FKs (``auth.users``, ``auth.agent_registrations``) are
granted REFERENCES via the root Alembic head (revision 002).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

metadata = MetaData(schema="ingest")


class Base(DeclarativeBase):
    metadata = metadata


class GameLogFile(Base):
    __tablename__ = "game_log_files"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    first_uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "content_type IN ('match-log', 'decklist', 'unknown')",
            name="ck_game_log_files_content_type",
        ),
        CheckConstraint(
            "size_bytes >= 0",
            name="ck_game_log_files_size_nonneg",
        ),
    )


class UserUpload(Base):
    __tablename__ = "user_uploads"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sha256: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("ingest.game_log_files.sha256"),
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_registration_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.agent_registrations.id", ondelete="CASCADE"),
        nullable=False,
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)

    __table_args__ = (
        Index("ix_user_uploads_user_uploaded_at", "user_id", "uploaded_at"),
        Index("ix_user_uploads_sha256", "sha256"),
    )
