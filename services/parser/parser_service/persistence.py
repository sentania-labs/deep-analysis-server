"""Persist a :class:`ParsedMatch` to the parser schema."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from parser_service.models import Game, GameState, Match
from parser_service.parsing.models import ParsedMatch


async def persist_match(
    session: AsyncSession,
    parsed: ParsedMatch,
    sha256: str,
    user_id: int,
) -> Match:
    """Insert a parsed match (plus games and per-turn states).

    Idempotent on ``(sha256, user_id)`` at the database layer — uses
    ``INSERT ... ON CONFLICT (sha256, user_id) DO NOTHING RETURNING id``
    so two consumers racing on the same upload cannot both create child
    rows. If the conflict path is hit, we resolve the existing row and
    skip the child writes entirely (they were already persisted by the
    winner).
    """
    new_id = uuid.uuid4()
    insert_stmt = (
        pg_insert(Match)
        .values(
            id=new_id,
            sha256=sha256,
            user_id=user_id,
            format=parsed.format,
            event_type=parsed.event_type,
            players=parsed.players,
            match_result=parsed.match_result,
            winner=parsed.winner,
            game_count=parsed.game_count,
            parsed_at=datetime.now(UTC),
            played_at=parsed.played_at,
        )
        .on_conflict_do_nothing(constraint="uq_matches_sha256_user")
        .returning(Match.id)
    )
    inserted_id = (await session.execute(insert_stmt)).scalar_one_or_none()

    if inserted_id is None:
        # Another worker won the race — return the canonical row, do not
        # re-insert children.
        existing = (
            await session.execute(
                select(Match).where(Match.sha256 == sha256, Match.user_id == user_id)
            )
        ).scalar_one()
        await session.commit()
        return existing

    for parsed_game in parsed.games:
        game = Game(
            id=uuid.uuid4(),
            match_id=inserted_id,
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
    match = (await session.execute(select(Match).where(Match.id == inserted_id))).scalar_one()
    return match
