"""Persist a :class:`ParsedMatch` to the parser schema."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from parser_service.models import Game, GameEventRow, GamePlayer, GameState, Match
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.settings import PARSER_VERSION


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
