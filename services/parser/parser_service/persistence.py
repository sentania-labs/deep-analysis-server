"""Persist a :class:`ParsedMatch` to the parser schema."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
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

    Idempotent on ``(sha256, user_id)`` — re-parsing the same upload
    for the same user returns the existing row without duplicating.
    """
    existing = (
        await session.execute(
            select(Match).where(Match.sha256 == sha256, Match.user_id == user_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    match = Match(
        sha256=sha256,
        user_id=user_id,
        format=parsed.format,
        event_type=parsed.event_type,
        players=parsed.players,
        match_result=parsed.match_result,
        winner=parsed.winner,
        game_count=parsed.game_count,
        parsed_at=datetime.now(UTC),
    )
    session.add(match)
    await session.flush()  # populate match.id

    for parsed_game in parsed.games:
        game = Game(
            id=uuid.uuid4(),
            match_id=match.id,
            game_number=parsed_game.game_number,
            winner=parsed_game.winner,
            result=parsed_game.result,
        )
        session.add(game)
        await session.flush()  # populate game.id

        for turn in parsed_game.turns:
            session.add(
                GameState(
                    game_id=game.id,
                    turn_number=turn.turn_number,
                    active_player=turn.active_player,
                    player_states={
                        name: snap.model_dump() for name, snap in turn.players.items()
                    },
                    stack=[entry.model_dump() for entry in turn.stack],
                )
            )

    await session.commit()
    return match
