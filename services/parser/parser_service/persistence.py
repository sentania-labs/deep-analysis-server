"""Persist a :class:`ParsedMatch` to the parser schema."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from parser_service.models import Game, GameState, Match
from parser_service.parsing.models import ParsedMatch
from parser_service.settings import PARSER_VERSION


async def persist_match(
    session: AsyncSession,
    parsed: ParsedMatch,
    sha256: str,
    user_id: int,
) -> Match:
    """Insert or update a parsed match (plus games and per-turn states).

    Idempotent on ``(sha256, user_id)`` at the database layer — uses
    ``INSERT ... ON CONFLICT (sha256, user_id) DO UPDATE`` so that
    re-parses (e.g. from the backfill scanner after a parser upgrade)
    overwrite the previous row's metadata and stamp the current
    ``parsed_with_version``.
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
    )
    upsert_stmt = insert_stmt.on_conflict_do_update(
        constraint="uq_matches_sha256_user",
        set_={
            "format": insert_stmt.excluded.format,
            "event_type": insert_stmt.excluded.event_type,
            "players": insert_stmt.excluded.players,
            "match_result": insert_stmt.excluded.match_result,
            "winner": insert_stmt.excluded.winner,
            "game_count": insert_stmt.excluded.game_count,
            "parsed_at": insert_stmt.excluded.parsed_at,
            "played_at": insert_stmt.excluded.played_at,
            "parsed_with_version": insert_stmt.excluded.parsed_with_version,
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

    await session.commit()
    match = (await session.execute(select(Match).where(Match.id == match_id))).scalar_one()
    return match
