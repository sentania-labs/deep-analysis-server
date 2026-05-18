"""SQLAlchemy models for the parser service.

Three tables in the ``parser`` schema:

- ``matches`` — one row per parsed match. Carries match metadata
  (format, event, players, result) plus attribution to the source
  upload (sha256, user_id).
- ``games`` — one row per game inside a match. Game-level result.
- ``game_states`` — one row per turn snapshot per game. JSONB columns
  hold the per-player zone contents, life totals, mana pool, and the
  stack at the start of that turn.

Cross-schema columns (``sha256``, ``user_id``) are stored as plain
columns rather than foreign keys: parser is built from the root
alembic head which runs before auth/ingest tables exist, so a hard
FK can't be declared at table-create time. The values are still
trustworthy because they originate from the ``file.ingested`` event
emitted by the ingest service after a successful upload commit.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

metadata = MetaData(schema="parser")


class Base(DeclarativeBase):
    metadata = metadata


class Match(Base):
    __tablename__ = "matches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    format: Mapped[str | None] = mapped_column(String(64), nullable=True)
    format_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    players: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")
    match_result: Mapped[str | None] = mapped_column(String(64), nullable=True)
    winner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    game_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    parsed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    played_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    parsed_with_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    archetype_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    hero_player_name: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("sha256", "user_id", name="uq_matches_sha256_user"),
        Index("ix_matches_user_id_parsed_at", "user_id", "parsed_at"),
        Index("ix_matches_sha256", "sha256"),
    )


class Game(Base):
    __tablename__ = "games"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    match_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.matches.id", ondelete="CASCADE"),
        nullable=False,
    )
    game_number: Mapped[int] = mapped_column(Integer, nullable=False)
    winner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    result: Mapped[str | None] = mapped_column(String(64), nullable=True)
    on_play: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    play_first: Mapped[str | None] = mapped_column(String(255), nullable=True)
    opening_hand_sizes: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")

    __table_args__ = (
        UniqueConstraint("match_id", "game_number", name="uq_games_match_game_number"),
        Index("ix_games_match_id", "match_id"),
    )


class GameState(Base):
    __tablename__ = "game_states"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    game_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.games.id", ondelete="CASCADE"),
        nullable=False,
    )
    turn_number: Mapped[int] = mapped_column(Integer, nullable=False)
    active_player: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Per-player snapshot: {"<player_name>": {"life": int, "zones": {...}, "mana_pool": {...}}}
    player_states: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )
    # Ordered list of stack entries at the start of the turn.
    stack: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")

    __table_args__ = (
        UniqueConstraint(
            "game_id", "turn_number", "active_player", name="uq_game_states_game_turn"
        ),
        Index("ix_game_states_game_id", "game_id"),
    )


class GameEventRow(Base):
    """Discrete game action — the event-stream complement to zone snapshots.

    Each row captures a single verb (cast, play, draw, discard, etc.)
    preserving information that is lost when actions are folded into
    accumulated zone lists.  ``seq`` orders events within a game.
    """

    __tablename__ = "game_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    game_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.games.id", ondelete="CASCADE"),
        nullable=False,
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    verb: Mapped[str] = mapped_column(Text, nullable=False)
    card_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    player: Mapped[str] = mapped_column(Text, nullable=False)
    turn_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_card: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("game_id", "seq", name="uq_game_events_game_seq"),
        Index("ix_game_events_game_id", "game_id"),
        Index("ix_game_events_game_id_turn", "game_id", "turn_number"),
    )


class GamePlayer(Base):
    """Per-game player row with hero/opponent identification.

    Denormalises the hero resolution that was previously done at query
    time.  ``is_local`` is ``True`` for the hero (uploader), ``False``
    for the opponent, or ``None`` when identification failed.
    ``on_play`` indicates whether *this* player chose to play first.
    ``mulligan_count`` is ``7 - opening_hand_size`` (0 for a full hand).
    """

    __tablename__ = "game_players"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    game_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.games.id", ondelete="CASCADE"),
        nullable=False,
    )
    player_name: Mapped[str] = mapped_column(Text, nullable=False)
    is_local: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    on_play: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    mulligan_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        UniqueConstraint("game_id", "player_name", name="uq_game_players_game_player"),
        Index("ix_game_players_game_id", "game_id"),
    )
