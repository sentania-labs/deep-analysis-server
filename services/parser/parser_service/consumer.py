"""Redis pub/sub consumer for ``file.ingested`` events.

One worker per process. On each event:

1. Read the raw bytes from the shared archive at the published sha.
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
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import async_sessionmaker

from common.events import FILE_INGESTED, MATCH_PARSED, FileIngestedPayload, MatchParsedPayload
from common.format_inference import collect_card_names, infer_format_for_match
from common.redis_client import EventPublisher
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
        raw_root: Path,
        parser: LogParser | None = None,
        publisher: EventPublisher | None = None,
        max_log_bytes: int | None = None,
    ) -> None:
        self._redis = redis_client
        self._sessionmaker = sessionmaker
        self._raw_root = raw_root
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
            await self.handle_event(sha, int(user_id))
        else:
            _log.debug("skipping unknown content_type sha=%s ct=%s", sha, content_type)

    async def handle_event(self, sha256: str, user_id: int) -> ParsedMatch | None:
        """Test-friendly entry point — reads, parses, persists, publishes."""
        try:
            content = read_raw(sha256, self._raw_root, max_bytes=self._max_log_bytes)
        except RawFileNotFoundError:
            _log.warning("raw file missing for sha=%s; skipping", sha256)
            return None
        except RawFileTooLargeError:
            _log.warning("raw file exceeds size ceiling sha=%s; skipping", sha256)
            return None
        except OSError:
            _log.exception("failed to read raw file sha=%s", sha256)
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
                _log.debug("archetype classification failed sha=%s", sha256)

            # Card game stats materialization — best-effort.
            try:
                await _materialize_card_game_stats(session, match, parsed, hero_player_name)
                await session.commit()
            except Exception:  # noqa: BLE001
                _log.debug("card_game_stats materialization failed sha=%s", sha256)
                await session.rollback()

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
    ) -> None:
        """Handle a decklist (grouping XML) upload — parse and persist."""
        try:
            content = read_raw(
                sha256, self._raw_root, hint_ext=".xml", max_bytes=self._max_log_bytes
            )
        except RawFileNotFoundError:
            _log.warning("raw grouping file missing for sha=%s; skipping", sha256)
            return
        except RawFileTooLargeError:
            _log.warning("raw grouping file exceeds size ceiling sha=%s; skipping", sha256)
            return
        except OSError:
            _log.exception("failed to read raw grouping file sha=%s", sha256)
            return

        parsed = parse_grouping_xml(content)
        if parsed is None:
            _log.warning("grouping XML unparseable sha=%s user_id=%s", sha256, user_id)
            return

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
                return

        _log.info(
            "deck composition parsed sha=%s user_id=%s type=%s name=%s items=%d",
            sha256,
            user_id,
            parsed.grouping_type,
            parsed.name,
            len(parsed.items),
        )


# ---------------------------------------------------------------------------
# Helpers — card collection per side, card_game_stats materialization
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


async def _materialize_card_game_stats(
    session: Any,
    match: Any,
    parsed: ParsedMatch,
    hero_player_name: str | None,
) -> None:
    """Write card_game_stats rows from game events.

    One row per (game_id, card_name, is_local). Aggregates seen/cast/played
    counts from game_events, resolves oracle_id from catalog.cards, and
    records win/loss from the game winner and game_players.

    Uses raw SQL INSERT ... ON CONFLICT for performance and to target the
    ``analytics`` schema (the parser ORM's metadata is bound to ``parser``).

    Skips materialization entirely when hero identity is unknown — without
    hero attribution, both players' events would collapse onto the same
    ``(game_id, card_name, is_local=False)`` key, overwriting each other.
    """
    if not parsed.games:
        return

    if not hero_player_name:
        _log.warning(
            "skipping card_game_stats: hero identity unknown match_id=%s",
            match.id,
        )
        return

    # Pre-fetch oracle_id lookup: card_name → oracle_id
    all_card_names: set[str] = set()
    for game in parsed.games:
        for evt in game.events:
            if evt.card_name:
                all_card_names.add(evt.card_name)
    if not all_card_names:
        return

    oracle_map: dict[str, str | None] = {}
    try:
        rows = (
            await session.execute(
                sa_text("SELECT name, oracle_id FROM catalog.cards WHERE name = ANY(:names)"),
                {"names": sorted(all_card_names)},
            )
        ).all()
        for name, oid in rows:
            oracle_map[str(name)] = str(oid) if oid else None
    except Exception:  # noqa: BLE001
        _log.debug("oracle_id lookup failed; proceeding without oracle_ids")

    # Build per-game game_id mapping from persistence. We need the actual
    # game UUIDs from the DB. Query them by match_id + game_number.
    game_id_rows = (
        await session.execute(
            sa_text("SELECT game_number, id FROM parser.games WHERE match_id = :mid"),
            {"mid": match.id},
        )
    ).all()
    game_id_map: dict[int, str] = {int(r[0]): str(r[1]) for r in game_id_rows}

    # Build game_players is_local map: game_id → {player_name_lower: is_local}
    gp_rows = (
        await session.execute(
            sa_text(
                "SELECT gp.game_id, gp.player_name, gp.is_local "
                "FROM parser.game_players gp "
                "JOIN parser.games g ON g.id = gp.game_id "
                "WHERE g.match_id = :mid"
            ),
            {"mid": match.id},
        )
    ).all()
    is_local_map: dict[str, dict[str, bool | None]] = {}
    for gid, pname, is_local in gp_rows:
        gid_str = str(gid)
        if gid_str not in is_local_map:
            is_local_map[gid_str] = {}
        is_local_map[gid_str][str(pname).lower()] = is_local

    # Delete existing card_game_stats for this match (reparse support).
    await session.execute(
        sa_text("DELETE FROM analytics.card_game_stats WHERE match_id = :mid"),
        {"mid": match.id},
    )

    insert_values: list[dict[str, Any]] = []

    for parsed_game in parsed.games:
        game_id = game_id_map.get(parsed_game.game_number)
        if not game_id:
            continue

        # Aggregate events by (card_name, player)
        card_player_agg: dict[tuple[str, str], dict[str, int]] = {}
        # First-cast turn per (card_name, player): min turn_number of any
        # cast event. None if the card was seen but never cast.
        card_player_first_cast: dict[tuple[str, str], int] = {}
        for evt in parsed_game.events:
            if evt.card_name is None:
                continue
            key = (evt.card_name, evt.player)
            agg = card_player_agg.setdefault(key, {"seen": 0, "cast": 0, "played": 0})
            agg["seen"] += 1
            if evt.verb == "cast":
                agg["cast"] += 1
                existing = card_player_first_cast.get(key)
                if existing is None or evt.turn_number < existing:
                    card_player_first_cast[key] = evt.turn_number
            elif evt.verb == "play":
                agg["played"] += 1

        is_postboard = parsed_game.game_number > 1
        game_winner = parsed_game.winner

        # Get the is_local map for this game
        gp_local = is_local_map.get(game_id, {})

        for (card_name, player), counts in card_player_agg.items():
            # Determine is_local from game_players
            is_local_val = gp_local.get(player.lower())
            if is_local_val is None:
                # Fallback: compare to hero_player_name
                if hero_player_name:
                    is_local_val = player.lower() == hero_player_name.lower()
                else:
                    is_local_val = False  # default to opponent if unknown

            # Determine won
            won: bool | None = None
            if game_winner:
                player_won = game_winner.lower() == player.lower()
                won = player_won if is_local_val else not player_won
                # won is from the local (hero) perspective:
                # if is_local and player won → won=True
                # if not is_local and player won → won=False (hero lost)
                won = player_won == is_local_val if is_local_val is not None else None

            oracle_id = oracle_map.get(card_name)

            insert_values.append(
                {
                    "match_id": str(match.id),
                    "game_id": game_id,
                    "oracle_id": oracle_id,
                    "card_name": card_name,
                    "is_local": is_local_val,
                    "seen": counts["seen"],
                    "cast": counts["cast"],
                    "played": counts["played"],
                    "is_postboard": is_postboard,
                    "won": won,
                    "quantity": counts["seen"],
                    "game_number": parsed_game.game_number,
                    "first_cast_turn": card_player_first_cast.get((card_name, player)),
                }
            )

    if insert_values:
        # Batch insert using raw SQL for cross-schema write.
        for row in insert_values:
            # ``cast`` is a SQL reserved word — quoting is required in
            # column lists and SET-clause LHS (qualified ``EXCLUDED.cast``
            # parses fine unquoted). Before this fix the INSERT raised
            # syntax-error every call and the best-effort try/except in
            # the caller swallowed it, so no rows ever landed.
            await session.execute(
                sa_text(
                    "INSERT INTO analytics.card_game_stats "
                    "(match_id, game_id, oracle_id, card_name, is_local, "
                    ' seen, "cast", played, is_postboard, won, quantity, game_number, '
                    " first_cast_turn) "
                    "VALUES (:match_id, :game_id, :oracle_id::uuid, :card_name, :is_local, "
                    " :seen, :cast, :played, :is_postboard, :won, :quantity, :game_number, "
                    " :first_cast_turn) "
                    "ON CONFLICT (game_id, card_name, is_local) DO UPDATE SET "
                    ' seen = EXCLUDED.seen, "cast" = EXCLUDED.cast, played = EXCLUDED.played, '
                    " won = EXCLUDED.won, quantity = EXCLUDED.quantity, "
                    " oracle_id = EXCLUDED.oracle_id, "
                    " first_cast_turn = EXCLUDED.first_cast_turn"
                ),
                row,
            )
