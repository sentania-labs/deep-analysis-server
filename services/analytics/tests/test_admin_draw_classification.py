"""Tests for the admin-matches draw-classification helper (#71).

The admin matches list previously rendered any null-winner match
with ``game_count > 0`` as "Draw". That over-counted partial parses
where the parser had only seen a game header. The new helper mirrors
``stats._classify_match`` — a draw requires at least two players with
equal, nonzero game-win counts.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Analytics main.py reads JWT public key + DB/Redis URLs at import."""
    out = tmp_path_factory.mktemp("analytics-jwt-keys-admin-draw")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(pub_pem)
    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")
    yield pub_path


def _helper():
    from analytics_service.main import _is_true_draw

    return _is_true_draw


def test_two_players_equal_one_game_each_is_draw() -> None:
    """1-1 with neither player ahead — a real Magic draw."""
    assert _helper()({"alice": 1, "bob": 1}) is True


def test_two_players_equal_two_games_each_is_draw() -> None:
    """2-2 (a 5-game match with a drawn deciding game) — still a draw."""
    assert _helper()({"alice": 2, "bob": 2}) is True


def test_unequal_wins_is_not_draw() -> None:
    """Whoever has more wins is the match winner, not a draw."""
    assert _helper()({"alice": 2, "bob": 1}) is False


def test_only_one_player_with_wins_is_not_draw() -> None:
    """A 1-0 in progress: alice has a game, bob has none — still in
    progress, not a draw."""
    assert _helper()({"alice": 1}) is False


def test_no_winners_at_all_is_not_draw() -> None:
    """No games have resolved — this is the partial-parse case the
    "Draw" template bug was triggering on. Must NOT be a draw."""
    assert _helper()({}) is False


def test_three_way_equal_is_still_draw() -> None:
    """Defensive: if a future format ever produces 3+ players, equal
    nonzero wins should still count as a draw."""
    assert _helper()({"a": 1, "b": 1, "c": 1}) is True
