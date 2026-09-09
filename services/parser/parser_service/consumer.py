"""Redis pub/sub consumer for ``file.ingested`` events.

One worker per process. On each event:

1. Read the raw bytes from the object archive at the published sha.
2. Route by ``content_type``:
   - ``match-log``: parse with :class:`LogParser`, persist match data,
     publish ``match.parsed``.
   - ``decklist``: parse grouping XML, persist deck composition.
3. Persistence and publish failures are logged and do not kill the
   worker — pub/sub delivery is best-effort, and the goal is to keep
   draining events. Hard programmer errors still propagate.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as redis
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import async_sessionmaker

from common.events import FILE_INGESTED, MATCH_PARSED, FileIngestedPayload, MatchParsedPayload
from common.format_inference import collect_card_names, infer_format_for_match
from common.redis_client import EventPublisher
from common.storage import ObjectStorageError, ObjectStore
from parser_service import analytics_client
from parser_service.models import MatchArchetype
from parser_service.parsing import LogParser, ParsedMatch
from parser_service.parsing.grouping_parser import parse_grouping_xml
from parser_service.persistence import link_deck_to_match, persist_deck_composition, persist_match
from parser_service.settings import get_settings as get_parser_settings
from parser_service.storage import RawFileNotFoundError, RawFileTooLargeError, read_raw

_log = logging.getLogger("parser.consumer")


class ParserConsumer:
    def __init__(
        self,
        redis_client: redis.Redis,
        sessionmaker: async_sessionmaker[Any],
        store: ObjectStore,
        parser: LogParser | None = None,
        publisher: EventPublisher | None = None,
        max_log_bytes: int | None = None,
        key_prefix: str = "raw",
    ) -> None:
        self._redis = redis_client
        self._sessionmaker = sessionmaker
        self._store = store
        self._key_prefix = key_prefix
        self._parser = parser or LogParser()
        self._publisher = publisher or EventPublisher(redis_client)
        self._max_log_bytes = max_log_bytes
        self._stop_event = asyncio.Event()

    def stop(self) -> None:
        """Signal the consumer to stop on the next iteration."""
        self._stop_event.set()

    async def run(self) -> None:
        """Subscribe and drain events until :meth:`stop` is called."""
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(FILE_INGESTED)
        _log.info("parser consumer subscribed channel=%s", FILE_INGESTED)
        try:
            async for message in self._iter_messages(pubsub):
                if self._stop_event.is_set():
                    break
                await self._handle(message)
        finally:
            await pubsub.unsubscribe(FILE_INGESTED)
            await pubsub.aclose()

    async def _resolve_hero(
        self,
        user_id: int,
        players: list[str],
    ) -> str | None:
        """Look up the uploader's MTGO usernames and match against
        the parsed player list to identify the hero.

        Returns the matching player name from the parsed list, or
        ``None`` if no match is found (falls back to ``players[0]``
        in that case).
        """
        if not players:
            return None
        try:
            async with self._sessionmaker() as session:
                row = (
                    await session.execute(
                        sa_text("SELECT mtgo_usernames FROM auth.users WHERE id = :uid"),
                        {"uid": user_id},
                    )
                ).scalar_one_or_none()
        except Exception:  # noqa: BLE001
            _log.debug("failed to load mtgo_usernames for user_id=%s", user_id)
            return str(players[0]) if players else None

        mtgo_usernames: list[str] | None = None
        if row and isinstance(row, list):
            mtgo_usernames = row

        if mtgo_usernames:
            names_lower = {n.lower() for n in mtgo_usernames}
            for p in players:
                if str(p).lower() in names_lower:
                    return str(p)

        # Fallback: first player in the list (parser convention puts
        # the uploader-side account first).
        return str(players[0])

    async def _iter_messages(self, pubsub: Any) -> AsyncIterator[dict[str, Any]]:
        while not self._stop_event.is_set():
            try:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — keep draining on transient errors
                _log.exception("redis pubsub get_message failed")
                await asyncio.sleep(1.0)
                continue
            if msg is None:
                continue
            yield msg

    async def _handle(self, message: dict[str, Any]) -> None:
        try:
            raw_data = message.get("data")
            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode("utf-8", errors="replace")
            if not isinstance(raw_data, str):
                _log.warning("dropping event with non-string data: %r", message)
                return
            payload: FileIngestedPayload = json.loads(raw_data)
        except (ValueError, TypeError):
            _log.exception("failed to decode file.ingested payload: %r", message)
            return

        sha = payload.get("sha256")
        user_id = payload.get("user_id")
        content_type = payload.get("content_type", "match-log")

        if not sha or user_id is None:
            _log.warning("ignoring event missing sha256/user_id: %r", payload)
            return

        if content_type == "decklist":
            file_mtime = payload.get("file_mtime")
            await self.handle_decklist_event(
                sha,
                int(user_id),
                file_mtime=float(file_mtime) if file_mtime is not None else None,
            )
        elif content_type == "match-log":
            await self.handle_event(
                sha,
                int(user_id),
                agent_classification=_coerce_agent_classification(
                    payload.get("agent_classification")
                ),
            )
        else:
            _log.debug("skipping unknown content_type sha=%s ct=%s", sha, content_type)

    async def handle_event(
        self,
        sha256: str,
        user_id: int,
        agent_classification: str | None = None,
    ) -> ParsedMatch | None:
        """Test-friendly entry point: reads, parses, persists, publishes.

        ``agent_classification`` is the agent's tail-scan verdict from
        the upload ("complete" or "inconclusive"), or None for agents
        that predate the field. It only annotates the review reason;
        the server parse stays authoritative.
        """
        try:
            content = await read_raw(
                self._store,
                sha256,
                key_prefix=self._key_prefix,
                max_bytes=self._max_log_bytes,
            )
        except RawFileNotFoundError:
            _log.warning("raw object missing for sha=%s; skipping", sha256)
            return None
        except RawFileTooLargeError:
            _log.warning("raw object exceeds size ceiling sha=%s; skipping", sha256)
            return None
        except (ObjectStorageError, OSError):
            # Store unreachable. Leave the file unparsed: the backfill
            # scan retries it once storage is back.
            _log.exception("failed to read raw object sha=%s", sha256)
            return None

        parsed = self._parser.parse(content)
        if _is_empty_parse(parsed):
            # No games at all — nothing the agent has captured. There's
            # no admin value in surfacing these; drop on the floor.
            _log.warning(
                "skipping empty parse sha=%s user_id=%s games=0 match_winner=%s",
                sha256,
                user_id,
                parsed.winner,
            )
            return parsed

        review_status: str | None = None
        review_reason: str | None = None
        if _is_partial_parse(parsed):
            # Games observed but no resolved winners anywhere — could
            # be an in-progress MTGO snapshot the agent caught during
            # a natural lull, or a genuine broken parse. Persist with
            # ``pending_review`` so an admin can decide; a later, more
            # complete snapshot of the same logical match will UPDATE
            # this row back to ``review_status=NULL`` automatically
            # (see persist_match → _update_match_row).
            _log.info(
                "holding-pen partial parse sha=%s user_id=%s games=%d match_winner=%s",
                sha256,
                user_id,
                len(parsed.games),
                parsed.winner,
            )
            review_status = "pending_review"
            review_reason = _build_review_reason(parsed, agent_classification)

        # Resolve the hero player name from auth.users.mtgo_usernames.
        hero_player_name = await self._resolve_hero(user_id, parsed.players)

        async with self._sessionmaker() as session:
            try:
                match = await persist_match(
                    session,
                    parsed,
                    sha256,
                    user_id,
                    hero_player_name=hero_player_name,
                    review_status=review_status,
                    review_reason=review_reason,
                )
            except Exception:
                _log.exception("persist failed sha=%s user_id=%s", sha256, user_id)
                await session.rollback()
                return parsed

            match_id = match.id
            match_id_str = str(match_id)

            # Skip format inference when an admin has manually set the
            # format — format_source='manual' is authoritative and must
            # survive both reparsing and inference.
            card_names: list[str] = []
            if not match.format and match.format_source != "manual":
                try:
                    card_names = collect_card_names(parsed)
                    if card_names:
                        fmt = await infer_format_for_match(session, card_names)
                        if fmt:
                            match.format = fmt
                            match.format_source = "inferred"
                            await session.commit()
                except Exception:  # noqa: BLE001
                    _log.debug("format inference failed sha=%s", sha256)

            # Archetype classification — best-effort, never fails the parse.
            # Classify BOTH sides (hero + opponent) and write MatchArchetype rows.
            try:
                settings = get_parser_settings()
                if settings.analytics_service_url:
                    hero_cards, opponent_cards = _collect_cards_by_side(
                        parsed,
                        hero_player_name,
                    )
                    if not hero_cards:
                        # Fallback: use the old battlefield-scan method
                        hero_cards = card_names or collect_card_names(parsed)

                    # Classify hero side
                    hero_result = (
                        await analytics_client.classify_with_confidence(
                            settings.analytics_service_url,
                            hero_cards,
                        )
                        if hero_cards
                        else None
                    )

                    # Classify opponent side
                    opp_result = (
                        await analytics_client.classify_with_confidence(
                            settings.analytics_service_url,
                            opponent_cards,
                        )
                        if opponent_cards
                        else None
                    )

                    # Write MatchArchetype rows
                    ma_values: list[dict[str, Any]] = []
                    if hero_player_name and hero_result:
                        ma_values.append(
                            {
                                "match_id": match_id,
                                "player_name": hero_player_name,
                                "archetype_id": hero_result.archetype_id,
                                "confidence": hero_result.confidence,
                            }
                        )
                    # Find opponent name
                    opponent_name = _get_opponent_name(parsed.players, hero_player_name)
                    if opponent_name and opp_result:
                        ma_values.append(
                            {
                                "match_id": match_id,
                                "player_name": opponent_name,
                                "archetype_id": opp_result.archetype_id,
                                "confidence": opp_result.confidence,
                            }
                        )
                    if ma_values:
                        ma_stmt = pg_insert(MatchArchetype).values(ma_values)
                        ma_stmt = ma_stmt.on_conflict_do_update(
                            constraint="uq_match_archetypes_match_player",
                            set_={
                                "archetype_id": ma_stmt.excluded.archetype_id,
                                "confidence": ma_stmt.excluded.confidence,
                            },
                        )
                        await session.execute(ma_stmt)

                    # Backward compat: keep match.archetype_id = hero-side result
                    if hero_result and match.archetype_id != hero_result.archetype_id:
                        match.archetype_id = hero_result.archetype_id
                    await session.commit()
            except Exception:  # noqa: BLE001
                await session.rollback()
                _log.debug("archetype classification failed sha=%s", sha256)

            # Deck-to-match linking — best-effort.
            try:
                await link_deck_to_match(session, match_id, user_id, match.format)
            except Exception:  # noqa: BLE001
                _log.debug("deck-to-match link failed sha=%s", sha256)

        out: MatchParsedPayload = {
            "match_id": match_id_str,
            "user_id": str(user_id),
            "game_count": parsed.game_count,
            "parsed_at": datetime.now(UTC).isoformat(),
        }
        try:
            await self._publisher.publish(MATCH_PARSED, dict(out))
        except Exception:  # noqa: BLE001 — best-effort
            _log.exception("match.parsed publish failed match_id=%s", match_id_str)

        _log.info(
            "match parsed match_id=%s sha=%s user_id=%s games=%s",
            match_id_str,
            sha256,
            user_id,
            parsed.game_count,
        )
        return parsed

    async def _lookup_original_filename(
        self,
        sha256: str,
        user_id: int,
    ) -> str | None:
        """Look up the original filename from ingest.user_uploads."""
        try:
            async with self._sessionmaker() as session:
                row = (
                    await session.execute(
                        sa_text(
                            "SELECT original_filename FROM ingest.user_uploads "
                            "WHERE sha256 = :sha AND user_id = :uid "
                            "ORDER BY uploaded_at DESC LIMIT 1"
                        ),
                        {"sha": sha256, "uid": user_id},
                    )
                ).scalar_one_or_none()
                return str(row) if row else None
        except Exception:  # noqa: BLE001
            _log.debug("failed to look up original_filename sha=%s user_id=%s", sha256, user_id)
            return None

    async def handle_decklist_event(
        self,
        sha256: str,
        user_id: int,
        file_mtime: float | None = None,
    ) -> bool:
        """Handle a decklist (grouping XML) upload: parse and persist.

        Returns True only when a deck composition was actually parsed
        and persisted. Every early return (missing raw object, size
        ceiling, read error, unparseable XML, persist failure) returns
        False so callers can count real work. :func:`scan_unparsed`
        keys its processed counter on this.
        """
        try:
            content = await read_raw(
                self._store,
                sha256,
                key_prefix=self._key_prefix,
                max_bytes=self._max_log_bytes,
            )
        except RawFileNotFoundError:
            _log.warning("raw grouping object missing for sha=%s; skipping", sha256)
            return False
        except RawFileTooLargeError:
            _log.warning("raw grouping object exceeds size ceiling sha=%s; skipping", sha256)
            return False
        except (ObjectStorageError, OSError):
            _log.exception("failed to read raw grouping object sha=%s", sha256)
            return False

        parsed = parse_grouping_xml(content)
        if parsed is None:
            _log.warning("grouping XML unparseable sha=%s user_id=%s", sha256, user_id)
            return False

        original_filename = await self._lookup_original_filename(sha256, user_id)

        async with self._sessionmaker() as session:
            try:
                await persist_deck_composition(
                    session,
                    parsed,
                    sha256,
                    user_id,
                    original_filename=original_filename,
                    file_mtime=file_mtime,
                )
            except Exception:
                _log.exception("persist deck composition failed sha=%s user_id=%s", sha256, user_id)
                await session.rollback()
                return False

        _log.info(
            "deck composition parsed sha=%s user_id=%s type=%s name=%s items=%d",
            sha256,
            user_id,
            parsed.grouping_type,
            parsed.name,
            len(parsed.items),
        )
        return True


# ---------------------------------------------------------------------------
# Helpers — card collection per side
# ---------------------------------------------------------------------------


def _is_empty_parse(parsed: ParsedMatch) -> bool:
    """True when the parse extracted no games at all.

    Distinct from :func:`_is_partial_parse`: an empty parse is pure
    garbage (no header, no game data, nothing observable) and there's
    no admin value in surfacing it for review. Empty parses are dropped
    outright; partial parses with games but no winners land in the
    holding pen.
    """
    return not parsed.games


def _is_partial_parse(parsed: ParsedMatch) -> bool:
    """Decide whether a parse is "winner-less" — holding-pen candidate.

    Returns True when there is no match-level winner AND no game has a
    resolved winner either. That catches snapshots where MTGO has
    emitted a game header but the game has not finished yet (the
    agent's 5-second stability gate fires during natural lulls in
    play).

    A real Magic draw is *not* partial: each game has a winner field
    but neither player wins the majority, so ``parsed.winner`` is None
    while ``parsed.games[*].winner`` is populated. That case must be
    persisted normally.

    Under v0.9.8 the consumer no longer drops partial parses outright
    — it now persists them with ``review_status='pending_review'`` so
    an admin can choose to accept or reject.
    """
    if parsed.winner:
        return False
    return not any(g.winner for g in parsed.games)


_VALID_AGENT_CLASSIFICATIONS = frozenset({"complete", "inconclusive"})

# Appended to the parser's own reason so an admin can tell the two
# causes apart at a glance in the review UI:
#   - "inconclusive": the agent's tail scan saw no completion signal,
#     so the file itself is almost certainly truncated. Nothing to fix
#     server-side.
#   - "complete": the file looked finished to the agent but the parser
#     still could not resolve a winner. That is a parser gap worth
#     investigating.
_AGENT_VERDICT_SUFFIX = {
    "inconclusive": ("; agent tail scan: inconclusive (no match-completion signal in the file)"),
    "complete": (
        "; agent tail scan: complete (file looked finished, parser could not resolve a winner)"
    ),
}


def _coerce_agent_classification(raw: object) -> str | None:
    """Normalize the event's ``agent_classification`` field.

    Anything that is not one of the two contracted values (including a
    missing field from an older agent) degrades to None rather than
    failing the parse.
    """
    if isinstance(raw, str) and raw in _VALID_AGENT_CLASSIFICATIONS:
        return raw
    if raw is not None:
        _log.debug("ignoring unrecognized agent_classification: %r", raw)
    return None


def _build_review_reason(parsed: ParsedMatch, agent_classification: str | None = None) -> str:
    """Build a concise, human-readable reason for why a parse is partial.

    Called only when ``_is_partial_parse(parsed)`` is True -- i.e., games
    exist but no match-level or per-game winner was resolved.

    When the agent sent a tail-scan verdict, it is appended as a
    distinct clause. Without one the string is byte-identical to the
    pre-#125 wording.
    """
    game_count = len(parsed.games)
    games_with_winners = sum(1 for g in parsed.games if g.winner)
    plural = "s" if game_count != 1 else ""

    if games_with_winners == 0:
        reason = f"No game winners resolved ({game_count} game{plural} observed)"
    else:
        # Safety net -- theoretically unreachable when _is_partial_parse is
        # True (it requires *no* game winners).
        reason = f"Partial: {games_with_winners} of {game_count} game{plural} have winners"

    suffix = _AGENT_VERDICT_SUFFIX.get(_coerce_agent_classification(agent_classification) or "")
    return reason + suffix if suffix else reason


def _collect_cards_by_side(
    parsed: ParsedMatch,
    hero_player_name: str | None,
) -> tuple[list[str], list[str]]:
    """Collect unique card names for hero and opponent from game events.

    Returns (hero_cards, opponent_cards) as sorted lists.
    """
    hero_cards: set[str] = set()
    opp_cards: set[str] = set()
    for game in parsed.games:
        for evt in game.events:
            if evt.card_name is None:
                continue
            if hero_player_name and evt.player.lower() == hero_player_name.lower():
                hero_cards.add(evt.card_name)
            else:
                opp_cards.add(evt.card_name)
    return sorted(hero_cards), sorted(opp_cards)


def _get_opponent_name(
    players: list[str],
    hero_player_name: str | None,
) -> str | None:
    """Return the opponent's name from the player list."""
    if not hero_player_name or not players:
        return None
    hero_lower = hero_player_name.lower()
    for p in players:
        if p.lower() != hero_lower:
            return p
    return None
