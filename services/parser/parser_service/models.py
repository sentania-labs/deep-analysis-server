"""SQLAlchemy models for the parser service.

Tables in the ``parser`` schema:

- ``matches`` — one row per parsed match. Carries match metadata
  (format, event, players, result) plus attribution to the source
  upload (sha256, user_id).
- ``games`` — one row per game inside a match. Game-level result.
- ``game_states`` — one row per turn snapshot per game. JSONB columns
  hold the per-player zone contents, life totals, mana pool, and the
  stack at the start of that turn.
- ``deck_compositions`` — one row per parsed MTGO grouping XML file.
- ``deck_composition_items`` — individual card entries within a deck.

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
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
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
    raw_match_id: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    # True when MTGO reports "Match Tied" — an intentional draw.
    # Distinguishes real draws from partial parses where no game
    # winners have been resolved yet (both show 0-0 game wins).
    match_tied: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # Holding-pen state for inconclusive parses. NULL = normal,
    # user-visible. ``'pending_review'`` = parse came in without a
    # match winner or any per-game winner; hidden from users and
    # analytics until an admin accepts (back to NULL) or rejects.
    # ``'rejected'`` = admin discarded; permanently hidden. The DB
    # CHECK constraint (alembic 025) enforces the allowed values.
    review_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    deck_composition_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.deck_compositions.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint("sha256", "user_id", name="uq_matches_sha256_user"),
        # Partial unique index on (raw_match_id, user_id) enforced only
        # when raw_match_id is non-null — created in alembic 024 with
        # postgresql_where because SQLAlchemy's UniqueConstraint can't
        # express the partial predicate directly.
        Index(
            "uq_matches_raw_match_id_user",
            "raw_match_id",
            "user_id",
            unique=True,
            postgresql_where=text("raw_match_id IS NOT NULL"),
        ),
        Index("ix_matches_user_id_parsed_at", "user_id", "parsed_at"),
        Index("ix_matches_sha256", "sha256"),
        Index("ix_matches_raw_match_id", "raw_match_id"),
        Index(
            "ix_matches_review_status",
            "review_status",
            postgresql_where=text("review_status IS NOT NULL"),
        ),
        CheckConstraint(
            "review_status IS NULL OR review_status IN ('pending_review', 'rejected')",
            name="ck_matches_review_status_valid",
        ),
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


class MatchArchetype(Base):
    """Per-player archetype classification for a match.

    Captures both hero and opponent archetype assignments with
    confidence scores.  The hero-side archetype is also written to
    ``matches.archetype_id`` for backward compatibility.
    """

    __tablename__ = "match_archetypes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    match_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.matches.id", ondelete="CASCADE"),
        nullable=False,
    )
    player_name: Mapped[str] = mapped_column(Text, nullable=False)
    archetype_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    __table_args__ = (
        UniqueConstraint("match_id", "player_name", name="uq_match_archetypes_match_player"),
        Index("ix_match_archetypes_match_id", "match_id"),
        Index("ix_match_archetypes_archetype_id", "archetype_id"),
    )


class DeckComposition(Base):
    """Parsed MTGO grouping XML file — one row per deck/wishlist/binder.

    Content-addressed via ``sha256`` (references ``ingest.game_log_files``).
    Only ``grouping_type='Deck'`` rows are linked to matches.
    """

    __tablename__ = "deck_compositions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    deck_uuid: Mapped[str | None] = mapped_column(Text, nullable=True)
    net_deck_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    grouping_type: Mapped[str] = mapped_column(Text, nullable=False)
    format_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    deck_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    file_mtime: Mapped[float | None] = mapped_column(Float, nullable=True)
    version_number: Mapped[int | None] = mapped_column(Integer, nullable=True, server_default="1")
    parsed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint("sha256", "user_id", name="uq_deck_compositions_sha256_user"),
        Index("ix_deck_compositions_user_id", "user_id"),
        Index("ix_deck_compositions_format_code", "format_code"),
    )


class DeckCompositionItem(Base):
    """Individual card entry within a deck composition.

    ``mtgo_id`` is the MTGO CatId.  ``card_name`` is resolved from
    ``catalog.cards`` at parse time and may be ``None`` if the CatId
    is not in the catalog.
    """

    __tablename__ = "deck_composition_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    deck_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.deck_compositions.id", ondelete="CASCADE"),
        nullable=False,
    )
    mtgo_id: Mapped[int] = mapped_column(Integer, nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    is_sideboard: Mapped[bool] = mapped_column(Boolean, nullable=False)
    card_name: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_deck_composition_items_deck_id", "deck_id"),
        Index("ix_deck_composition_items_mtgo_id", "mtgo_id"),
    )


class UserReparseCooldown(Base):
    """Per-user cooldown timestamp for self-service reparse.

    Single-row-per-user state backing ``POST /parser/me/reparse``. The
    handler updates this table with an atomic
    ``INSERT ... ON CONFLICT (user_id) DO UPDATE ... WHERE`` so the
    rate-limit check and the timestamp bump happen in one statement —
    preventing two concurrent requests from both passing the gate.
    """

    __tablename__ = "user_reparse_cooldown"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_reparse_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class DeckVersionLink(Base):
    """Version chain entry linking sequential uploads of the same deck.

    Tracks the diff (cards added/removed) between consecutive versions
    of a logical deck identity.  ``deck_identity`` is ``net_deck_id``
    when available, otherwise ``"<name>::<format_code>"``.
    """

    __tablename__ = "deck_version_links"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    deck_identity: Mapped[str] = mapped_column(Text, nullable=False)
    deck_composition_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.deck_compositions.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_composition_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parser.deck_compositions.id", ondelete="SET NULL"),
        nullable=True,
    )
    cards_added: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    cards_removed: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "deck_identity",
            "version_number",
            name="uq_deck_version_links_user_identity_version",
        ),
        Index("ix_deck_version_links_user_identity", "user_id", "deck_identity"),
        Index("ix_deck_version_links_composition_id", "deck_composition_id"),
    )
