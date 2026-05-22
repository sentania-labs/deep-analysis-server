"""Tests for persist_match's legacy-row upgrade path (#71, Codex P1).

Before this fix, ``persist_match`` keyed strictly on
``(raw_match_id, user_id)`` when ``raw_match_id`` was set. If a legacy
row existed for the same ``(sha256, user_id)`` with
``raw_match_id IS NULL`` (common during reparse or post-cleanup with
pruned raw bytes), the INSERT collided with ``uq_matches_sha256_user``
and raised ``IntegrityError``. The consumer's ``handle_event``
swallowed the failure and the parse was dropped on the floor — the
legacy row was stuck NULL forever.

These tests exercise the find-or-upsert behavior that replaced the
ON CONFLICT path: SELECT by precedence (raw_match_id first, then
sha256 with NULL raw_match_id), then UPDATE in place.

Gated on the ``DA_TEST_DATABASE_URL`` fixture (see conftest.py).
"""

from __future__ import annotations

import uuid

import pytest
from parser_service.models import Match
from parser_service.parsing.models import ParsedGame, ParsedMatch
from parser_service.persistence import persist_match
from sqlalchemy import select


def _make_parsed(
    raw_match_id: str | None,
    winner: str | None = "alice",
    games: int = 2,
) -> ParsedMatch:
    return ParsedMatch(
        raw_match_id=raw_match_id,
        players=["alice", "bob"],
        winner=winner,
        match_result=f"{games}-0" if winner else None,
        format="Legacy",
        games=[ParsedGame(game_number=i + 1, winner=winner) for i in range(games)],
    )


@pytest.mark.asyncio
async def test_legacy_row_upgraded_in_place(parser_session) -> None:
    """A legacy (sha256, user, raw_match_id=NULL) row gets *upgraded*
    when a fresh parse arrives carrying a real raw_match_id — no
    IntegrityError, raw_match_id is backfilled, and the row identity
    (its UUID primary key) is preserved."""
    legacy_id = uuid.uuid4()
    legacy = Match(
        id=legacy_id,
        sha256="X" * 64,
        user_id=1,
        raw_match_id=None,
        format="Modern",  # will be overwritten by the new parse
        players=["alice", "bob"],
        winner=None,  # legacy row predates winner extraction
        game_count=0,
    )
    parser_session.add(legacy)
    await parser_session.commit()

    new_uuid = "11111111-2222-3333-4444-555555555555"
    parsed = _make_parsed(raw_match_id=new_uuid, winner="alice", games=2)

    # The bug: this used to raise IntegrityError on the unique
    # constraint and the consumer dropped the parse.
    result = await persist_match(parser_session, parsed, sha256="X" * 64, user_id=1)

    assert result.id == legacy_id, "legacy row identity must be preserved"
    assert result.raw_match_id == new_uuid, "raw_match_id must be backfilled"
    assert result.winner == "alice"
    assert result.game_count == 2
    assert result.format == "Legacy"

    # Sanity: still exactly one row for this (sha256, user) pair.
    rows = (
        (
            await parser_session.execute(
                select(Match).where(Match.sha256 == "X" * 64, Match.user_id == 1)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_legacy_row_better_parse_not_clobbered(parser_session) -> None:
    """The quality gate still fires on legacy upgrade: a partial parse
    (no winner) arriving for a legacy row that already has a winner
    should not downgrade the stored fields. It should still backfill
    raw_match_id though — that's pure metadata."""
    legacy_id = uuid.uuid4()
    legacy = Match(
        id=legacy_id,
        sha256="Y" * 64,
        user_id=1,
        raw_match_id=None,
        format="Modern",
        players=["alice", "bob"],
        winner="alice",  # legacy row HAS a winner
        game_count=3,
    )
    parser_session.add(legacy)
    await parser_session.commit()

    new_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    partial = _make_parsed(raw_match_id=new_uuid, winner=None, games=0)

    result = await persist_match(parser_session, partial, sha256="Y" * 64, user_id=1)

    assert result.id == legacy_id
    assert result.winner == "alice", "better stored parse must not be downgraded"
    assert result.game_count == 3
    # Bookkeeping path still backfills raw_match_id onto the legacy row.
    assert result.raw_match_id == new_uuid


@pytest.mark.asyncio
async def test_raw_match_id_keyed_row_takes_precedence(parser_session) -> None:
    """When both candidate rows exist for the same user — a canonical
    row keyed on (raw_match_id) AND a legacy row with raw_match_id=NULL
    for a *different* sha256 — the raw_match_id match wins. The legacy
    row stays untouched."""
    canonical_uuid = "deadbeef-1111-2222-3333-444444444444"
    canonical_id = uuid.uuid4()
    legacy_id = uuid.uuid4()

    canonical = Match(
        id=canonical_id,
        sha256="A" * 64,
        user_id=1,
        raw_match_id=canonical_uuid,
        format="Legacy",
        players=["alice", "bob"],
        winner=None,
        game_count=1,
    )
    legacy_unrelated = Match(
        id=legacy_id,
        sha256="B" * 64,
        user_id=1,
        raw_match_id=None,
        format="Modern",
        players=["alice", "bob"],
        winner=None,
        game_count=0,
    )
    parser_session.add_all([canonical, legacy_unrelated])
    await parser_session.commit()

    # New parse re-targets the canonical row (same sha256 as canonical).
    parsed = _make_parsed(raw_match_id=canonical_uuid, winner="alice", games=2)
    result = await persist_match(parser_session, parsed, sha256="A" * 64, user_id=1)

    assert result.id == canonical_id, (
        "raw_match_id match must win — never fall through to sha256 path"
    )
    assert result.winner == "alice"

    # The unrelated legacy row (different sha256, no raw_match_id)
    # must be untouched by this parse.
    legacy_after = (
        await parser_session.execute(select(Match).where(Match.id == legacy_id))
    ).scalar_one()
    assert legacy_after.raw_match_id is None
    assert legacy_after.winner is None
    assert legacy_after.sha256 == "B" * 64


@pytest.mark.asyncio
async def test_brand_new_match_inserts(parser_session) -> None:
    """No existing row → INSERT. Baseline sanity check."""
    new_uuid = "12345678-1234-1234-1234-123456789012"
    parsed = _make_parsed(raw_match_id=new_uuid, winner="alice", games=2)

    result = await persist_match(parser_session, parsed, sha256="Z" * 64, user_id=42)

    assert result.raw_match_id == new_uuid
    assert result.user_id == 42
    assert result.winner == "alice"

    rows = (await parser_session.execute(select(Match).where(Match.user_id == 42))).scalars().all()
    assert len(rows) == 1
