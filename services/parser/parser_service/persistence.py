"""Persist parsed data to the parser schema.

Handles both :class:`ParsedMatch` (match logs) and
:class:`ParsedGrouping` (grouping XML deck compositions).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from parser_service.models import (
    DeckComposition,
    DeckCompositionItem,
    DeckVersionLink,
    Game,
    GameEventRow,
    GamePlayer,
    GameState,
    Match,
)
from parser_service.parsing.grouping_parser import ParsedGrouping, extract_deck_uuid
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.settings import PARSER_VERSION

_log = logging.getLogger("parser.persistence")


def _extract_player_names(
    parsed_game: ParsedGame,
    match_players: list[str],
) -> list[str]:
    """Determine the player names for a game.

    Prefers the match-level player list (canonical names); falls back
    to names extracted from the game's turns or opening hand sizes.
    """
    if match_players:
        return list(match_players)
    # Try opening hand sizes (dict keys are player names)
    if parsed_game.opening_hand_sizes:
        return list(parsed_game.opening_hand_sizes.keys())
    # Try turns — collect unique active_player / snapshot keys
    names: list[str] = []
    seen: set[str] = set()
    for turn in parsed_game.turns:
        for pname in turn.players:
            if pname not in seen:
                names.append(pname)
                seen.add(pname)
    return names


async def persist_match(
    session: AsyncSession,
    parsed: ParsedMatch,
    sha256: str,
    user_id: int,
    hero_player_name: str | None = None,
) -> Match:
    """Insert or update a parsed match (plus games and per-turn states).

    Idempotent on ``(sha256, user_id)`` at the database layer — uses
    ``INSERT ... ON CONFLICT (sha256, user_id) DO UPDATE`` so that
    re-parses (e.g. from the backfill scanner after a parser upgrade)
    overwrite the previous row's metadata and stamp the current
    ``parsed_with_version``.

    ``hero_player_name`` is the resolved MTGO username of the uploader,
    determined by cross-referencing ``auth.users.mtgo_usernames`` with
    the parsed player list.
    """
    now = datetime.now(UTC)
    new_id = uuid.uuid4()
    insert_stmt = pg_insert(Match).values(
        id=new_id,
        sha256=sha256,
        user_id=user_id,
        format=parsed.format,
        event_type=parsed.event_type,
        players=parsed.players,
        match_result=parsed.match_result,
        winner=parsed.winner,
        game_count=parsed.game_count,
        parsed_at=now,
        played_at=parsed.played_at,
        parsed_with_version=PARSER_VERSION,
        hero_player_name=hero_player_name,
    )
    # Preserve manual format overrides during reparse: if an admin has
    # set format_source='manual', the UPSERT must keep the existing
    # format and format_source rather than overwriting with the parsed
    # (or null) value.
    upsert_stmt = insert_stmt.on_conflict_do_update(
        constraint="uq_matches_sha256_user",
        set_={
            "format": text(
                "CASE WHEN matches.format_source = 'manual'"
                " THEN matches.format ELSE EXCLUDED.format END"
            ),
            "format_source": text(
                "CASE WHEN matches.format_source = 'manual'"
                " THEN matches.format_source ELSE EXCLUDED.format_source END"
            ),
            "event_type": insert_stmt.excluded.event_type,
            "players": insert_stmt.excluded.players,
            "match_result": insert_stmt.excluded.match_result,
            "winner": insert_stmt.excluded.winner,
            "game_count": insert_stmt.excluded.game_count,
            "parsed_at": insert_stmt.excluded.parsed_at,
            "played_at": insert_stmt.excluded.played_at,
            "parsed_with_version": insert_stmt.excluded.parsed_with_version,
            "hero_player_name": insert_stmt.excluded.hero_player_name,
        },
    ).returning(Match.id)

    match_id = (await session.execute(upsert_stmt)).scalar_one()

    # If this was an upsert (reparse), the id is the existing row's id,
    # not new_id. Either way we need to (re-)write children.
    is_reparse = match_id != new_id
    if is_reparse:
        # Clear stale children before re-inserting.
        # CASCADE on games.match_id → game_states.game_id handles states.
        await session.execute(delete(Game).where(Game.match_id == match_id))

    for parsed_game in parsed.games:
        game = Game(
            id=uuid.uuid4(),
            match_id=match_id,
            game_number=parsed_game.game_number,
            winner=parsed_game.winner,
            result=parsed_game.result,
            on_play=parsed_game.on_play,
            play_first=parsed_game.play_first,
            opening_hand_sizes=parsed_game.opening_hand_sizes,
        )
        session.add(game)
        await session.flush()  # populate game.id

        if parsed_game.turns:
            turn_values = [
                {
                    "game_id": game.id,
                    "turn_number": turn.turn_number,
                    "active_player": turn.active_player,
                    "player_states": {
                        name: snap.model_dump() for name, snap in turn.players.items()
                    },
                    "stack": [entry.model_dump() for entry in turn.stack],
                }
                for turn in parsed_game.turns
            ]
            gs_stmt = pg_insert(GameState).values(turn_values)
            gs_stmt = gs_stmt.on_conflict_do_update(
                constraint="uq_game_states_game_turn",
                set_={
                    "active_player": gs_stmt.excluded.active_player,
                    "player_states": gs_stmt.excluded.player_states,
                    "stack": gs_stmt.excluded.stack,
                },
            )
            await session.execute(gs_stmt)

        # Persist event stream (additive alongside snapshots).
        if parsed_game.events:
            event_values = [
                {
                    "game_id": game.id,
                    "seq": seq,
                    "verb": evt.verb,
                    "card_name": evt.card_name,
                    "player": evt.player,
                    "turn_number": evt.turn_number,
                    "source_card": evt.source_card,
                }
                for seq, evt in enumerate(parsed_game.events)
            ]
            ev_stmt = pg_insert(GameEventRow).values(event_values)
            ev_stmt = ev_stmt.on_conflict_do_update(
                constraint="uq_game_events_game_seq",
                set_={
                    "verb": ev_stmt.excluded.verb,
                    "card_name": ev_stmt.excluded.card_name,
                    "player": ev_stmt.excluded.player,
                    "turn_number": ev_stmt.excluded.turn_number,
                    "source_card": ev_stmt.excluded.source_card,
                },
            )
            await session.execute(ev_stmt)

        # Persist game_players rows — one per player per game.
        player_names = _extract_player_names(parsed_game, parsed.players)
        if player_names:
            gp_values = []
            for pname in player_names:
                is_local: bool | None = None
                if hero_player_name:
                    is_local = pname.lower() == hero_player_name.lower()
                on_play_flag: bool | None = None
                if parsed_game.play_first:
                    on_play_flag = pname.lower() == parsed_game.play_first.lower()
                mulligan_count: int | None = None
                hand_sizes = parsed_game.opening_hand_sizes or {}
                # Try exact match, then case-insensitive
                if pname in hand_sizes:
                    mulligan_count = max(0, 7 - int(hand_sizes[pname]))
                else:
                    for k, v in hand_sizes.items():
                        if k.lower() == pname.lower():
                            mulligan_count = max(0, 7 - int(v))
                            break
                gp_values.append(
                    {
                        "game_id": game.id,
                        "player_name": pname,
                        "is_local": is_local,
                        "on_play": on_play_flag,
                        "mulligan_count": mulligan_count,
                    }
                )
            gp_stmt = pg_insert(GamePlayer).values(gp_values)
            gp_stmt = gp_stmt.on_conflict_do_update(
                constraint="uq_game_players_game_player",
                set_={
                    "is_local": gp_stmt.excluded.is_local,
                    "on_play": gp_stmt.excluded.on_play,
                    "mulligan_count": gp_stmt.excluded.mulligan_count,
                },
            )
            await session.execute(gp_stmt)

    await session.commit()
    match = (await session.execute(select(Match).where(Match.id == match_id))).scalar_one()
    return match


# ---------------------------------------------------------------------------
# Deck composition persistence
# ---------------------------------------------------------------------------

# MTGO format code → system format string
FORMAT_CODE_MAP: dict[str, str] = {
    "CLEGACY": "Legacy",
    "CMODERN": "Modern",
    "CVINTAGE": "Vintage",
    "CPAUPER": "Pauper",
    "CPIONEER": "Pioneer",
    "CSTANDARD": "Standard",
}


async def resolve_mtgo_ids(
    session: AsyncSession,
    mtgo_ids: list[int],
) -> dict[int, str]:
    """Resolve MTGO catalog IDs to card names via ``catalog.cards``.

    Returns a mapping of mtgo_id → card name for all IDs that exist
    in the catalog.  Missing IDs are silently omitted.
    """
    if not mtgo_ids:
        return {}
    try:
        rows = (
            await session.execute(
                text("SELECT mtgo_id, name FROM catalog.cards WHERE mtgo_id = ANY(:ids)"),
                {"ids": mtgo_ids},
            )
        ).all()
        return {int(r[0]): str(r[1]) for r in rows}
    except Exception:  # noqa: BLE001
        _log.debug("catalog.cards mtgo_id lookup failed; proceeding without card names")
        return {}


def _compute_deck_identity(parsed: ParsedGrouping) -> str:
    """Derive a stable identity string for version linking.

    Prefers ``net_deck_id`` (MTGO's own deck ID); falls back to
    ``"<name>::<format_code>"`` for locally created decks.
    """
    if parsed.net_deck_id:
        return parsed.net_deck_id
    name_part = parsed.name or "unknown"
    fmt_part = parsed.format_code or "unknown"
    return f"{name_part}::{fmt_part}"


_CardDict = dict[str, Any]


def _compute_card_diff(
    old_items: list[_CardDict],
    new_items: list[_CardDict],
) -> tuple[list[_CardDict], list[_CardDict]]:
    """Compare two item lists and return (added, removed).

    Each item dict has keys: mtgo_id, card_name, quantity, is_sideboard.
    A card moving between main/sideboard counts as a remove + add.
    """
    _Key = tuple[int, bool]  # (mtgo_id, is_sideboard)

    old_map: dict[_Key, _CardDict] = {}
    for item in old_items:
        key: _Key = (int(item["mtgo_id"]), bool(item["is_sideboard"]))
        old_map[key] = item

    new_map: dict[_Key, _CardDict] = {}
    for item in new_items:
        key = (int(item["mtgo_id"]), bool(item["is_sideboard"]))
        new_map[key] = item

    added: list[_CardDict] = []
    removed: list[_CardDict] = []

    all_keys = set(old_map.keys()) | set(new_map.keys())
    for k in sorted(all_keys):
        old_entry = old_map.get(k)
        new_entry = new_map.get(k)
        if old_entry is None and new_entry is not None:
            added.append(new_entry)
        elif new_entry is None and old_entry is not None:
            removed.append(old_entry)
        elif (
            old_entry is not None
            and new_entry is not None
            and int(old_entry["quantity"]) != int(new_entry["quantity"])
        ):
            removed.append(old_entry)
            added.append(new_entry)

    return added, removed


async def persist_deck_composition(
    session: AsyncSession,
    parsed: ParsedGrouping,
    sha256: str,
    user_id: int,
    original_filename: str | None = None,
    file_mtime: float | None = None,
) -> DeckComposition:
    """Insert or update a parsed deck composition with its items.

    Idempotent on ``(sha256, user_id)`` — re-uploads overwrite the
    previous row's metadata.  CatId → card_name resolution is done
    here via ``catalog.cards.mtgo_id``.

    When ``file_mtime`` is provided (from the agent's upload), it is
    stored for version ordering.  After upserting the composition,
    a ``deck_version_links`` row is created to track the diff from
    the previous version of the same deck identity.
    """
    now = datetime.now(UTC)
    deck_uuid = extract_deck_uuid(original_filename)

    new_id = uuid.uuid4()
    insert_stmt = pg_insert(DeckComposition).values(
        id=new_id,
        sha256=sha256,
        user_id=user_id,
        deck_uuid=deck_uuid,
        net_deck_id=parsed.net_deck_id,
        name=parsed.name,
        grouping_type=parsed.grouping_type,
        format_code=parsed.format_code,
        deck_timestamp=parsed.deck_timestamp,
        file_mtime=file_mtime,
        parsed_at=now,
    )
    upsert_stmt = insert_stmt.on_conflict_do_update(
        constraint="uq_deck_compositions_sha256_user",
        set_={
            "deck_uuid": insert_stmt.excluded.deck_uuid,
            "net_deck_id": insert_stmt.excluded.net_deck_id,
            "name": insert_stmt.excluded.name,
            "grouping_type": insert_stmt.excluded.grouping_type,
            "format_code": insert_stmt.excluded.format_code,
            "deck_timestamp": insert_stmt.excluded.deck_timestamp,
            "file_mtime": insert_stmt.excluded.file_mtime,
            "parsed_at": insert_stmt.excluded.parsed_at,
        },
    ).returning(DeckComposition.id)

    deck_id = (await session.execute(upsert_stmt)).scalar_one()

    # If this was an upsert (re-upload), clear stale items before re-inserting.
    is_reparse = deck_id != new_id
    if is_reparse:
        await session.execute(
            delete(DeckCompositionItem).where(DeckCompositionItem.deck_id == deck_id),
        )

    # Resolve CatId → card_name in bulk.
    mtgo_ids = [item.cat_id for item in parsed.items]
    name_map = await resolve_mtgo_ids(session, mtgo_ids)

    new_item_dicts: list[_CardDict] = []
    if parsed.items:
        item_values = [
            {
                "deck_id": deck_id,
                "mtgo_id": item.cat_id,
                "quantity": item.quantity,
                "is_sideboard": item.is_sideboard,
                "card_name": name_map.get(item.cat_id),
            }
            for item in parsed.items
        ]
        await session.execute(pg_insert(DeckCompositionItem).values(item_values))
        new_item_dicts = [
            {
                "mtgo_id": item.cat_id,
                "card_name": name_map.get(item.cat_id),
                "quantity": item.quantity,
                "is_sideboard": item.is_sideboard,
            }
            for item in parsed.items
        ]

    # --- Deck version linking ---
    try:
        await _link_deck_version(
            session,
            deck_id=deck_id,
            user_id=user_id,
            parsed=parsed,
            new_item_dicts=new_item_dicts,
        )
    except Exception:  # noqa: BLE001 — version linking is best-effort
        _log.debug("deck version linking failed deck_id=%s", deck_id)

    await session.commit()
    deck = (
        await session.execute(
            select(DeckComposition).where(DeckComposition.id == deck_id),
        )
    ).scalar_one()
    return deck


async def _link_deck_version(
    session: AsyncSession,
    deck_id: uuid.UUID,
    user_id: int,
    parsed: ParsedGrouping,
    new_item_dicts: list[_CardDict],
) -> None:
    """Create a version link for this deck composition.

    Finds the previous version of the same deck identity, computes
    the card-level diff, assigns the next version number, and inserts
    a ``deck_version_links`` row.
    """
    deck_identity = _compute_deck_identity(parsed)

    # Find the most recent version link for this identity + user.
    prev_link_row = (
        await session.execute(
            select(DeckVersionLink)
            .where(
                DeckVersionLink.user_id == user_id,
                DeckVersionLink.deck_identity == deck_identity,
            )
            .order_by(DeckVersionLink.version_number.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if prev_link_row is not None:
        next_version = prev_link_row.version_number + 1
        prev_comp_id = prev_link_row.deck_composition_id
    else:
        next_version = 1
        prev_comp_id = None

    # Update version_number on the composition row.
    await session.execute(
        text("UPDATE parser.deck_compositions SET version_number = :ver WHERE id = :did"),
        {"ver": next_version, "did": deck_id},
    )

    # Compute diff if there is a previous version.
    cards_added: list[_CardDict] | None = None
    cards_removed: list[_CardDict] | None = None
    if prev_comp_id is not None:
        prev_items_rows = (
            await session.execute(
                select(
                    DeckCompositionItem.mtgo_id,
                    DeckCompositionItem.card_name,
                    DeckCompositionItem.quantity,
                    DeckCompositionItem.is_sideboard,
                ).where(DeckCompositionItem.deck_id == prev_comp_id)
            )
        ).all()
        old_item_dicts: list[_CardDict] = [
            {
                "mtgo_id": r[0],
                "card_name": r[1],
                "quantity": r[2],
                "is_sideboard": r[3],
            }
            for r in prev_items_rows
        ]
        cards_added, cards_removed = _compute_card_diff(old_item_dicts, new_item_dicts)

    link = DeckVersionLink(
        user_id=user_id,
        deck_identity=deck_identity,
        deck_composition_id=deck_id,
        version_number=next_version,
        previous_composition_id=prev_comp_id,
        cards_added=cards_added,
        cards_removed=cards_removed,
    )
    session.add(link)


async def link_deck_to_match(
    session: AsyncSession,
    match_id: uuid.UUID,
    user_id: int,
    match_format: str | None,
) -> uuid.UUID | None:
    """Best-effort: find the most likely deck composition for a match.

    Links by user, format, and ``grouping_type='Deck'``.  When
    multiple candidates exist, picks the one with the most recent
    ``deck_timestamp`` (the most recently saved version of the deck).

    Returns the linked ``deck_composition_id`` or ``None``.
    """
    if not match_format:
        return None

    # Reverse-map system format → MTGO format codes.
    reverse_map: dict[str, list[str]] = {}
    for code, fmt in FORMAT_CODE_MAP.items():
        reverse_map.setdefault(fmt, []).append(code)

    format_codes = reverse_map.get(match_format)
    if not format_codes:
        return None

    try:
        row = (
            await session.execute(
                text(
                    "SELECT id FROM parser.deck_compositions "
                    "WHERE user_id = :uid "
                    "  AND grouping_type = 'Deck' "
                    "  AND format_code = ANY(:codes) "
                    "ORDER BY deck_timestamp DESC NULLS LAST, parsed_at DESC "
                    "LIMIT 1"
                ),
                {"uid": user_id, "codes": format_codes},
            )
        ).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        _log.debug("deck-to-match link query failed match_id=%s", match_id)
        return None

    if row is None:
        return None

    deck_comp_id = row
    try:
        await session.execute(
            text("UPDATE parser.matches SET deck_composition_id = :did WHERE id = :mid"),
            {"did": deck_comp_id, "mid": match_id},
        )
        await session.commit()
    except Exception:  # noqa: BLE001
        _log.debug("failed to write deck_composition_id on match %s", match_id)
        await session.rollback()
        return None

    return deck_comp_id
