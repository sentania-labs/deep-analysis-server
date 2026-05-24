"""Round-trip for the analytics.card_game_stats.first_cast_turn column.

CI runs ``alembic upgrade head`` against a real Postgres before invoking
pytest in this directory, so reaching this test means migration 027
applied successfully. The body proves the column exists, accepts both
INTEGER and NULL, and survives a DELETE.

Skipped locally unless ``DATABASE_URL`` (sync driver) is set.
"""

from __future__ import annotations

import os
import uuid

import pytest


def _pg_url() -> str | None:
    raw = os.environ.get("DATABASE_URL")
    if not raw:
        return None
    # psycopg / SQLAlchemy use ``postgresql+psycopg://...``; strip the
    # SQLAlchemy dialect prefix for the raw psycopg connect string.
    return raw.replace("postgresql+psycopg://", "postgresql://", 1)


@pytest.fixture
def pg_conn() -> object:
    url = _pg_url()
    if not url:
        pytest.skip("DATABASE_URL not set — skipping DB round-trip")
    psycopg = pytest.importorskip("psycopg")
    conn = psycopg.connect(url)
    try:
        yield conn
    finally:
        conn.close()


def test_first_cast_turn_column_exists(pg_conn: object) -> None:
    """After alembic upgrade head, the column is present with the right type."""
    with pg_conn.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute(
            """
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'analytics'
              AND table_name = 'card_game_stats'
              AND column_name = 'first_cast_turn'
            """
        )
        row = cur.fetchone()
    assert row is not None, "first_cast_turn column missing after migration"
    data_type, is_nullable = row
    assert data_type == "integer"
    assert is_nullable == "YES"


def test_first_cast_turn_accepts_int_and_null(pg_conn: object) -> None:
    """The column round-trips an integer and a NULL value."""
    match_id = uuid.uuid4()
    game_id_a = uuid.uuid4()
    game_id_b = uuid.uuid4()
    with pg_conn.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute(
            """
            INSERT INTO analytics.card_game_stats
                (match_id, game_id, card_name, is_local, seen, cast, played,
                 is_postboard, won, quantity, game_number, first_cast_turn)
            VALUES
                (%s, %s, %s, true, 1, 1, 0, false, true, 1, 1, %s),
                (%s, %s, %s, true, 1, 0, 0, false, false, 1, 1, NULL)
            """,
            (
                match_id,
                game_id_a,
                "Lightning Bolt",
                3,
                match_id,
                game_id_b,
                "Mountain",
            ),
        )
        cur.execute(
            """
            SELECT card_name, first_cast_turn
            FROM analytics.card_game_stats
            WHERE match_id = %s
            ORDER BY card_name
            """,
            (match_id,),
        )
        rows = dict(cur.fetchall())
        # Cleanup so we don't leave fixture rows in CI's shared database.
        cur.execute(
            "DELETE FROM analytics.card_game_stats WHERE match_id = %s",
            (match_id,),
        )
    pg_conn.commit()  # type: ignore[attr-defined]

    assert rows["Lightning Bolt"] == 3
    assert rows["Mountain"] is None
