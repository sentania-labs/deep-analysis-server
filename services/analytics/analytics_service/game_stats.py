"""Game-level analytics endpoints.

Provides play/draw win-rate splits, pre-board vs post-board performance,
mulligan frequency by opening hand size, and game-length distribution.
All endpoints filter by ``user_id`` from the verified JWT and identify
the "hero" player via ``auth.users.mtgo_usernames``, falling back to
``players[0]`` when no MTGO username matches.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user

router = APIRouter(prefix="/analytics/stats", tags=["game-stats"])


def _escape_like(value: str) -> str:
    """Escape SQL LIKE/ILIKE wildcard characters."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class WinRateBucket(BaseModel):
    total: int = 0
    wins: int = 0
    win_rate: float = 0.0


class PlayDrawResponse(BaseModel):
    on_play: WinRateBucket = Field(default_factory=WinRateBucket)
    on_draw: WinRateBucket = Field(default_factory=WinRateBucket)


class PrePostBoardResponse(BaseModel):
    preboard: WinRateBucket = Field(default_factory=WinRateBucket)
    postboard: WinRateBucket = Field(default_factory=WinRateBucket)


class MulliganBucket(BaseModel):
    hand_size: int
    total: int = 0
    wins: int = 0
    win_rate: float = 0.0


class GameLengthBucket(BaseModel):
    bucket: str
    total: int = 0
    wins: int = 0
    losses: int = 0


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


async def _load_mtgo_usernames(db: AsyncSession, user_id: int) -> list[str] | None:
    """Load MTGO usernames for the given user from auth schema."""
    try:
        row = (
            await db.execute(
                text("SELECT mtgo_usernames FROM auth.users WHERE id = :uid"),
                {"uid": user_id},
            )
        ).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        return None
    if row and isinstance(row, list):
        return row
    return None


def _identify_hero(
    players: list[Any] | None,
    mtgo_usernames: list[str] | None,
) -> str | None:
    """Return the hero player name from the player list."""
    if not players:
        return None
    if mtgo_usernames:
        names_lower = {n.lower() for n in mtgo_usernames}
        for p in players:
            if str(p).lower() in names_lower:
                return str(p)
    return str(players[0])


def _is_hero_winner(winner: str | None, hero: str | None) -> bool | None:
    """Return True if hero won, False if hero lost, None if indeterminate."""
    if winner is None or hero is None:
        return None
    return winner.lower() == hero.lower()


def _wr(wins: int, total: int) -> float:
    return (wins / total) * 100.0 if total else 0.0


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


async def _load_games_with_context(
    db: AsyncSession,
    user_id: int,
    format_filter: str | None = None,
    opponent: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """Load all games with match context for a user.

    Returns a list of dicts with keys: game_number, winner, on_play,
    play_first, opening_hand_sizes, players, format.
    """
    where = "WHERE m.user_id = :user_id"
    params: dict[str, Any] = {"user_id": user_id}
    if format_filter:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format_filter
    if opponent:
        where += " AND m.players::text ILIKE :opp_pattern ESCAPE '\\'"
        params["opp_pattern"] = f"%{_escape_like(opponent)}%"
    if date_from:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date >= :date_from"
        params["date_from"] = date_from
    if date_to:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date <= :date_to"
        params["date_to"] = date_to

    rows = (
        await db.execute(
            text(
                f"""
                SELECT g.game_number, g.winner, g.on_play, g.play_first,
                       g.opening_hand_sizes, m.players, m.format, g.id
                FROM parser.games g
                JOIN parser.matches m ON m.id = g.match_id
                {where}
                ORDER BY m.parsed_at DESC, g.game_number
                """
            ),
            params,
        )
    ).all()
    return [
        {
            "game_number": int(r[0]),
            "winner": r[1],
            "on_play": r[2],
            "play_first": r[3],
            "opening_hand_sizes": r[4] if r[4] else {},
            "players": list(r[5]) if r[5] else [],
            "format": r[6],
            "game_id": r[7],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/play-draw", response_model=PlayDrawResponse)
async def get_play_draw(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    date_from: Annotated[str | None, Query()] = None,
    date_to: Annotated[str | None, Query()] = None,
) -> PlayDrawResponse:
    """Win rate on the play vs on the draw."""
    games = await _load_games_with_context(
        db, user.user_id, format, opponent=opponent, date_from=date_from, date_to=date_to
    )
    names = await _load_mtgo_usernames(db, user.user_id)

    play_wins = play_total = 0
    draw_wins = draw_total = 0

    for g in games:
        if g["on_play"] is None:
            continue
        hero = _identify_hero(g["players"], names)
        won = _is_hero_winner(g["winner"], hero)
        if won is None:
            continue
        if g["on_play"]:
            play_total += 1
            if won:
                play_wins += 1
        else:
            draw_total += 1
            if won:
                draw_wins += 1

    return PlayDrawResponse(
        on_play=WinRateBucket(
            total=play_total, wins=play_wins, win_rate=_wr(play_wins, play_total)
        ),
        on_draw=WinRateBucket(
            total=draw_total, wins=draw_wins, win_rate=_wr(draw_wins, draw_total)
        ),
    )


@router.get("/preboard-postboard", response_model=PrePostBoardResponse)
async def get_preboard_postboard(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    date_from: Annotated[str | None, Query()] = None,
    date_to: Annotated[str | None, Query()] = None,
) -> PrePostBoardResponse:
    """Win rate in game 1 (pre-board) vs games 2-3 (post-board)."""
    games = await _load_games_with_context(
        db, user.user_id, format, opponent=opponent, date_from=date_from, date_to=date_to
    )
    names = await _load_mtgo_usernames(db, user.user_id)

    pre_wins = pre_total = 0
    post_wins = post_total = 0

    for g in games:
        hero = _identify_hero(g["players"], names)
        won = _is_hero_winner(g["winner"], hero)
        if won is None:
            continue
        if g["game_number"] == 1:
            pre_total += 1
            if won:
                pre_wins += 1
        else:
            post_total += 1
            if won:
                post_wins += 1

    return PrePostBoardResponse(
        preboard=WinRateBucket(total=pre_total, wins=pre_wins, win_rate=_wr(pre_wins, pre_total)),
        postboard=WinRateBucket(
            total=post_total, wins=post_wins, win_rate=_wr(post_wins, post_total)
        ),
    )


@router.get("/mulligans", response_model=list[MulliganBucket])
async def get_mulligans(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    date_from: Annotated[str | None, Query()] = None,
    date_to: Annotated[str | None, Query()] = None,
) -> list[MulliganBucket]:
    """Frequency and win rate by opening hand size."""
    games = await _load_games_with_context(
        db, user.user_id, format, opponent=opponent, date_from=date_from, date_to=date_to
    )
    names = await _load_mtgo_usernames(db, user.user_id)

    buckets: dict[int, dict[str, int]] = {}

    for g in games:
        hero = _identify_hero(g["players"], names)
        if hero is None:
            continue
        hand_sizes = g.get("opening_hand_sizes") or {}
        # Try exact match, then case-insensitive
        hand_size: int | None = None
        if hero in hand_sizes:
            hand_size = int(hand_sizes[hero])
        else:
            for k, v in hand_sizes.items():
                if k.lower() == hero.lower():
                    hand_size = int(v)
                    break
        if hand_size is None:
            continue

        b = buckets.setdefault(hand_size, {"total": 0, "wins": 0})
        b["total"] += 1
        won = _is_hero_winner(g["winner"], hero)
        if won:
            b["wins"] += 1

    result = []
    for hs in sorted(buckets, reverse=True):
        b = buckets[hs]
        result.append(
            MulliganBucket(
                hand_size=hs,
                total=b["total"],
                wins=b["wins"],
                win_rate=_wr(b["wins"], b["total"]),
            )
        )
    return result


@router.get("/game-length", response_model=list[GameLengthBucket])
async def get_game_length(
    user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
    format: Annotated[str | None, Query()] = None,
    opponent: Annotated[str | None, Query()] = None,
    date_from: Annotated[str | None, Query()] = None,
    date_to: Annotated[str | None, Query()] = None,
) -> list[GameLengthBucket]:
    """Turns distribution bucketed into ranges."""
    names = await _load_mtgo_usernames(db, user.user_id)

    where = "WHERE m.user_id = :user_id"
    params: dict[str, Any] = {"user_id": user.user_id}
    if format:
        where += " AND LOWER(m.format) = LOWER(:format)"
        params["format"] = format
    if opponent:
        where += " AND m.players::text ILIKE :opp_pattern ESCAPE '\\'"
        params["opp_pattern"] = f"%{_escape_like(opponent)}%"
    if date_from:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date >= :date_from"
        params["date_from"] = date_from
    if date_to:
        where += " AND COALESCE(m.played_at, m.parsed_at)::date <= :date_to"
        params["date_to"] = date_to

    rows = (
        await db.execute(
            text(
                f"""
                SELECT g.id, g.winner, m.players,
                       MAX(gs.turn_number) AS max_turn
                FROM parser.games g
                JOIN parser.matches m ON m.id = g.match_id
                LEFT JOIN parser.game_states gs ON gs.game_id = g.id
                {where}
                GROUP BY g.id, g.winner, m.players
                HAVING MAX(gs.turn_number) IS NOT NULL
                """
            ),
            params,
        )
    ).all()

    _BUCKETS = [
        ("1-3", 1, 3),
        ("4-6", 4, 6),
        ("7-9", 7, 9),
        ("10-12", 10, 12),
        ("13+", 13, 999),
    ]
    counts: dict[str, dict[str, int]] = {
        label: {"total": 0, "wins": 0, "losses": 0} for label, _, _ in _BUCKETS
    }

    for _game_id, winner, players, max_turn in rows:
        turn = int(max_turn)
        hero = _identify_hero(list(players) if players else [], names)
        won = _is_hero_winner(winner, hero)
        for label, lo, hi in _BUCKETS:
            if lo <= turn <= hi:
                counts[label]["total"] += 1
                if won is True:
                    counts[label]["wins"] += 1
                elif won is False:
                    counts[label]["losses"] += 1
                break

    return [
        GameLengthBucket(
            bucket=label,
            total=counts[label]["total"],
            wins=counts[label]["wins"],
            losses=counts[label]["losses"],
        )
        for label, _, _ in _BUCKETS
    ]
