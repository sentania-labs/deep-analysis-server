"""Card game stats materializer — subscribes to ``match.parsed`` events.

Moved from the parser service (consumer._materialize_card_game_stats) to
the analytics service so that the analytics schema owns writes to its own
``card_game_stats`` table.  The parser no longer writes to analytics.*
tables at all.

The materializer reads parsed game data from ``parser.*`` tables and
oracle_id lookups from ``catalog.cards`` (cross-schema reads, which are
allowed) and writes to ``analytics.card_game_stats`` (its own schema).

Idempotent: uses DELETE + INSERT so re-materialization on duplicate
``match.parsed`` events or backfill re-runs produces the same result.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from common.redis_client import get_redis

_log = logging.getLogger("analytics.card_materializer")

# Indirection for asyncio.sleep so tests can patch backoff delays.
_async_sleep = asyncio.sleep


async def materialize_card_game_stats(
    session: AsyncSession,
    match_id: str,
    user_id: int,
) -> None:
    """Materialize card_game_stats rows for a single match.

    Reads parsed game data from parser.* tables, resolves oracle_ids
    from catalog.cards, and writes per-game per-card stat rows into
    analytics.card_game_stats.

    Parameters
    ----------
    session:
        An async SQLAlchemy session with access to parser, catalog,
        and analytics schemas.
    match_id:
        UUID of the match (as string).
    user_id:
        Owner of the match — used only for logging context.
    """
    # Load hero_player_name from the match row.
    hero_row = (
        await session.execute(
            sa_text("SELECT hero_player_name FROM parser.matches WHERE id = CAST(:mid AS uuid)"),
            {"mid": match_id},
        )
    ).scalar_one_or_none()

    hero_player_name: str | None = str(hero_row) if hero_row else None

    if not hero_player_name:
        _log.warning(
            "skipping card_game_stats: hero identity unknown match_id=%s",
            match_id,
        )
        return

    # Load game events from parser.game_events via parser.games.
    game_id_rows = (
        await session.execute(
            sa_text("SELECT game_number, id FROM parser.games WHERE match_id = CAST(:mid AS uuid)"),
            {"mid": match_id},
        )
    ).all()

    if not game_id_rows:
        return

    # Load game_events for all games in this match.
    event_rows = (
        await session.execute(
            sa_text(
                "SELECT ge.game_id, ge.turn_number, ge.verb, ge.card_name, ge.player "
                "FROM parser.game_events ge "
                "JOIN parser.games g ON g.id = ge.game_id "
                "WHERE g.match_id = CAST(:mid AS uuid) "
                "AND ge.card_name IS NOT NULL"
            ),
            {"mid": match_id},
        )
    ).all()

    if not event_rows:
        return

    # Pre-fetch oracle_id lookup: card_name -> oracle_id
    all_card_names: set[str] = set()
    for row in event_rows:
        all_card_names.add(str(row[3]))

    oracle_map: dict[str, str | None] = {}
    if all_card_names:
        try:
            oracle_rows = (
                await session.execute(
                    sa_text("SELECT name, oracle_id FROM catalog.cards WHERE name = ANY(:names)"),
                    {"names": sorted(all_card_names)},
                )
            ).all()
            for name, oid in oracle_rows:
                oracle_map[str(name)] = str(oid) if oid else None
        except Exception:  # noqa: BLE001
            _log.debug("oracle_id lookup failed; proceeding without oracle_ids")

    # Build game_players is_local map: game_id -> {player_name_lower: is_local}
    gp_rows = (
        await session.execute(
            sa_text(
                "SELECT gp.game_id, gp.player_name, gp.is_local "
                "FROM parser.game_players gp "
                "JOIN parser.games g ON g.id = gp.game_id "
                "WHERE g.match_id = CAST(:mid AS uuid)"
            ),
            {"mid": match_id},
        )
    ).all()
    is_local_map: dict[str, dict[str, bool | None]] = {}
    for gid, pname, is_local in gp_rows:
        gid_str = str(gid)
        if gid_str not in is_local_map:
            is_local_map[gid_str] = {}
        is_local_map[gid_str][str(pname).lower()] = is_local

    # Load game winners: game_id -> winner
    game_winner_rows = (
        await session.execute(
            sa_text(
                "SELECT id, game_number, winner FROM parser.games "
                "WHERE match_id = CAST(:mid AS uuid)"
            ),
            {"mid": match_id},
        )
    ).all()
    game_winner_map: dict[str, str | None] = {}
    game_number_map: dict[str, int] = {}
    for gid, gnum, gwinner in game_winner_rows:
        gid_str = str(gid)
        game_winner_map[gid_str] = str(gwinner) if gwinner else None
        game_number_map[gid_str] = int(gnum)

    # Delete existing card_game_stats for this match (reparse support).
    await session.execute(
        sa_text("DELETE FROM analytics.card_game_stats WHERE match_id = CAST(:mid AS uuid)"),
        {"mid": match_id},
    )

    # Aggregate events by (game_id, card_name, player).
    # Structure: game_id -> (card_name, player) -> {seen, cast, played}
    game_card_agg: dict[str, dict[tuple[str, str], dict[str, int]]] = {}
    game_card_first_cast: dict[str, dict[tuple[str, str], int]] = {}

    for row in event_rows:
        game_id_val = str(row[0])
        turn_number = int(row[1])
        verb = str(row[2])
        card_name = str(row[3])
        player = str(row[4])

        if game_id_val not in game_card_agg:
            game_card_agg[game_id_val] = {}
            game_card_first_cast[game_id_val] = {}

        key = (card_name, player)
        agg = game_card_agg[game_id_val].setdefault(key, {"seen": 0, "cast": 0, "played": 0})
        agg["seen"] += 1
        if verb == "cast":
            agg["cast"] += 1
            existing = game_card_first_cast[game_id_val].get(key)
            if existing is None or turn_number < existing:
                game_card_first_cast[game_id_val][key] = turn_number
        elif verb == "play":
            agg["played"] += 1

    insert_values: list[dict[str, Any]] = []

    for game_id_val, card_agg in game_card_agg.items():
        game_number = game_number_map.get(game_id_val)
        if game_number is None:
            continue

        is_postboard = game_number > 1
        game_winner = game_winner_map.get(game_id_val)
        gp_local = is_local_map.get(game_id_val, {})

        for (card_name, player), counts in card_agg.items():
            # Determine is_local from game_players
            is_local_val = gp_local.get(player.lower())
            if is_local_val is None:
                # Fallback: compare to hero_player_name
                is_local_val = player.lower() == hero_player_name.lower()

            # Determine won from the hero perspective
            won: bool | None = None
            if game_winner:
                player_won = game_winner.lower() == player.lower()
                won = player_won == is_local_val if is_local_val is not None else None

            oracle_id = oracle_map.get(card_name)

            insert_values.append(
                {
                    "match_id": match_id,
                    "game_id": game_id_val,
                    "oracle_id": oracle_id,
                    "card_name": card_name,
                    "is_local": is_local_val,
                    "seen": counts["seen"],
                    "cast": counts["cast"],
                    "played": counts["played"],
                    "is_postboard": is_postboard,
                    "won": won,
                    "quantity": counts["seen"],
                    "game_number": game_number,
                    "first_cast_turn": game_card_first_cast.get(game_id_val, {}).get(
                        (card_name, player)
                    ),
                }
            )

    if insert_values:
        for insert_row in insert_values:
            await session.execute(
                sa_text(
                    "INSERT INTO analytics.card_game_stats "
                    "(match_id, game_id, oracle_id, card_name, is_local, "
                    ' seen, "cast", played, is_postboard, won, quantity, game_number, '
                    " first_cast_turn) "
                    "VALUES (CAST(:match_id AS uuid), CAST(:game_id AS uuid), "
                    "CAST(:oracle_id AS uuid), :card_name, :is_local, "
                    " :seen, :cast, :played, :is_postboard, :won, :quantity, :game_number, "
                    " :first_cast_turn) "
                    "ON CONFLICT (game_id, card_name, is_local) DO UPDATE SET "
                    ' seen = EXCLUDED.seen, "cast" = EXCLUDED.cast, played = EXCLUDED.played, '
                    " won = EXCLUDED.won, quantity = EXCLUDED.quantity, "
                    " oracle_id = EXCLUDED.oracle_id, "
                    " first_cast_turn = EXCLUDED.first_cast_turn"
                ),
                insert_row,
            )

    _log.info(
        "materialized %d card_game_stats rows match_id=%s user_id=%s",
        len(insert_values),
        match_id,
        user_id,
    )


# ---------------------------------------------------------------------------
# Backfill scan — catches events missed during disconnects/restarts
# ---------------------------------------------------------------------------

_BACKFILL_SQL = sa_text(
    """
    SELECT m.id::text, m.user_id
      FROM parser.matches m
     WHERE m.hero_player_name IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM analytics.card_game_stats cgs
            WHERE cgs.match_id = m.id
       )
     ORDER BY m.parsed_at DESC
     LIMIT :batch_size
    """
)


async def backfill_card_stats(
    sessionmaker: async_sessionmaker[Any],
    batch_size: int = 100,
) -> int:
    """Find matches missing card_game_stats and materialize them."""
    async with sessionmaker() as session:
        rows = (await session.execute(_BACKFILL_SQL, {"batch_size": batch_size})).all()

    if not rows:
        return 0

    _log.info("card stats backfill found %d unmaterialized matches", len(rows))
    processed = 0
    for match_id, user_id in rows:
        try:
            async with sessionmaker() as session:
                await materialize_card_game_stats(session, str(match_id), int(user_id))
                await session.commit()
                processed += 1
        except Exception:  # noqa: BLE001
            _log.exception("card stats backfill failed match_id=%s", match_id)

    _log.info("card stats backfill complete found=%d processed=%d", len(rows), processed)
    return processed


async def card_stats_backfill_loop(
    sessionmaker: async_sessionmaker[Any],
    interval_seconds: int = 300,
) -> None:
    """Periodically scan for matches missing card_game_stats."""
    _log.info("card stats backfill scanner started interval=%ds", interval_seconds)
    while True:
        try:
            await backfill_card_stats(sessionmaker)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            _log.exception("card stats backfill iteration failed")
        try:
            await _async_sleep(interval_seconds)
        except asyncio.CancelledError:
            raise


# ---------------------------------------------------------------------------
# Redis subscriber loop
# ---------------------------------------------------------------------------


async def card_materializer_loop(
    redis_url: str,
    sessionmaker: async_sessionmaker[Any],
) -> None:
    """Subscribe to ``match.parsed`` and materialize card_game_stats.

    Runs for the lifetime of the service. Wraps the subscription in a
    retry loop with exponential backoff so that a transient Redis
    disconnect does not permanently kill materialization.
    """
    backoff = 1.0
    max_backoff = 60.0
    while True:
        try:
            redis_client = await get_redis(redis_url)
            pubsub = redis_client.pubsub()
            await pubsub.subscribe("match.parsed")
            _log.info("card materializer subscribed to match.parsed")
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                backoff = 1.0  # reset on successful message
                try:
                    payload = json.loads(message["data"])
                    match_id = payload.get("match_id")
                    user_id = payload.get("user_id")
                    if match_id is not None and user_id is not None:
                        async with sessionmaker() as session:
                            try:
                                await materialize_card_game_stats(
                                    session, str(match_id), int(user_id)
                                )
                                await session.commit()
                            except Exception:  # noqa: BLE001
                                _log.exception(
                                    "card_game_stats materialization failed match_id=%s",
                                    match_id,
                                )
                                await session.rollback()
                except Exception:  # noqa: BLE001
                    _log.warning("card materializer message handling failed", exc_info=True)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            _log.warning(
                "card materializer loop lost Redis connection; retrying in %.0fs",
                backoff,
                exc_info=True,
            )
            await _async_sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
