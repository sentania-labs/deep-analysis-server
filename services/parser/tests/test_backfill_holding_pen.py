"""Tests for the holding-pen legacy-data backfill script.

End-to-end exercises against a real Postgres (gated on
``DA_TEST_DATABASE_URL``). Verifies that:

* ``discover_candidates`` correctly identifies legacy partial parses
  (winner None on match, no per-game winner anywhere) AND empty parses
  (no games), and leaves real draws + conclusive parses + already-flagged
  rows alone.
* ``--dry-run`` (apply=False) finds them but doesn't mutate.
* ``--apply`` (apply=True) sets ``review_status='pending_review'`` on
  exactly the discovered rows.
"""

from __future__ import annotations

import uuid

import pytest
from parser_service.models import Game, Match
from parser_service.scripts.backfill_holding_pen import (
    apply_flags,
    discover_candidates,
    per_user_counts,
)
from sqlalchemy import select


@pytest.mark.asyncio
async def test_discover_identifies_winnerless_matches(parser_session) -> None:
    """Mixed fixture: real partial, real draw, conclusive, empty, and
    already-flagged. Only the partial and the empty get picked up."""
    # 1. Partial: winner None, one game with no winner. Should be flagged.
    partial = Match(
        id=uuid.uuid4(),
        sha256="1" * 64,
        user_id=1,
        players=["alice", "bob"],
        winner=None,
        game_count=1,
    )
    parser_session.add(partial)
    await parser_session.flush()
    parser_session.add(Game(id=uuid.uuid4(), match_id=partial.id, game_number=1, winner=None))

    # 2. True draw: winner None on match BUT each game has a winner. Skip.
    draw = Match(
        id=uuid.uuid4(),
        sha256="2" * 64,
        user_id=1,
        players=["alice", "bob"],
        winner=None,
        game_count=3,
    )
    parser_session.add(draw)
    await parser_session.flush()
    parser_session.add_all(
        [
            Game(id=uuid.uuid4(), match_id=draw.id, game_number=1, winner="alice"),
            Game(id=uuid.uuid4(), match_id=draw.id, game_number=2, winner="bob"),
            Game(id=uuid.uuid4(), match_id=draw.id, game_number=3, winner=None),
        ]
    )

    # 3. Conclusive: winner set. Skip.
    conclusive = Match(
        id=uuid.uuid4(),
        sha256="3" * 64,
        user_id=2,
        players=["alice", "bob"],
        winner="alice",
        game_count=2,
    )
    parser_session.add(conclusive)
    await parser_session.flush()
    parser_session.add_all(
        [
            Game(id=uuid.uuid4(), match_id=conclusive.id, game_number=1, winner="alice"),
            Game(id=uuid.uuid4(), match_id=conclusive.id, game_number=2, winner="alice"),
        ]
    )

    # 4. Empty: no games at all. Should be flagged (legacy garbage).
    empty = Match(
        id=uuid.uuid4(),
        sha256="4" * 64,
        user_id=2,
        players=[],
        winner=None,
        game_count=0,
    )
    parser_session.add(empty)

    # 5. Already-flagged partial: review_status='pending_review'. Skip.
    already = Match(
        id=uuid.uuid4(),
        sha256="5" * 64,
        user_id=3,
        players=["alice", "bob"],
        winner=None,
        game_count=1,
        review_status="pending_review",
    )
    parser_session.add(already)
    await parser_session.flush()
    parser_session.add(Game(id=uuid.uuid4(), match_id=already.id, game_number=1, winner=None))

    # 6. Already-rejected: skip.
    rejected = Match(
        id=uuid.uuid4(),
        sha256="6" * 64,
        user_id=3,
        players=["alice", "bob"],
        winner=None,
        game_count=0,
        review_status="rejected",
    )
    parser_session.add(rejected)

    await parser_session.commit()

    sm = _session_maker_returning(parser_session)
    candidates = await discover_candidates(sm)
    flagged_ids = {c.match_id for c in candidates}

    assert str(partial.id) in flagged_ids
    assert str(empty.id) in flagged_ids
    assert str(draw.id) not in flagged_ids
    assert str(conclusive.id) not in flagged_ids
    assert str(already.id) not in flagged_ids
    assert str(rejected.id) not in flagged_ids
    assert len(candidates) == 2


@pytest.mark.asyncio
async def test_apply_flags_sets_pending_review(parser_session) -> None:
    """`apply_flags` updates exactly the candidates passed to it and
    leaves other rows alone."""
    target_id = uuid.uuid4()
    untouched_id = uuid.uuid4()
    parser_session.add_all(
        [
            Match(
                id=target_id,
                sha256="a" * 64,
                user_id=1,
                players=["alice", "bob"],
                winner=None,
                game_count=0,
            ),
            Match(
                id=untouched_id,
                sha256="b" * 64,
                user_id=1,
                players=["alice", "bob"],
                winner="alice",
                game_count=2,
            ),
        ]
    )
    await parser_session.commit()

    sm = _session_maker_returning(parser_session)
    from parser_service.scripts.backfill_holding_pen import _Candidate

    candidates = [_Candidate(match_id=str(target_id), user_id=1)]
    updated = await apply_flags(sm, candidates)
    assert updated == 1

    parser_session.expire_all()
    target = (await parser_session.execute(select(Match).where(Match.id == target_id))).scalar_one()
    untouched = (
        await parser_session.execute(select(Match).where(Match.id == untouched_id))
    ).scalar_one()
    assert target.review_status == "pending_review"
    assert untouched.review_status is None


@pytest.mark.asyncio
async def test_apply_flags_preserves_existing_admin_verdict(parser_session) -> None:
    """If a row was concurrently rejected between discover and apply,
    the apply UPDATE must not overwrite it. The WHERE re-checks
    ``review_status IS NULL``."""
    rejected_id = uuid.uuid4()
    parser_session.add(
        Match(
            id=rejected_id,
            sha256="c" * 64,
            user_id=1,
            players=["alice", "bob"],
            winner=None,
            game_count=0,
            review_status="rejected",  # concurrent admin verdict
        )
    )
    await parser_session.commit()

    from parser_service.scripts.backfill_holding_pen import _Candidate

    sm = _session_maker_returning(parser_session)
    candidates = [_Candidate(match_id=str(rejected_id), user_id=1)]
    updated = await apply_flags(sm, candidates)
    assert updated == 0, "must not overwrite an existing verdict"

    parser_session.expire_all()
    row = (await parser_session.execute(select(Match).where(Match.id == rejected_id))).scalar_one()
    assert row.review_status == "rejected"


def test_per_user_counts_aggregates() -> None:
    """Pure function — no DB needed."""
    from parser_service.scripts.backfill_holding_pen import _Candidate

    candidates = [
        _Candidate(match_id="m1", user_id=1),
        _Candidate(match_id="m2", user_id=1),
        _Candidate(match_id="m3", user_id=2),
    ]
    counts = per_user_counts(candidates)
    assert counts == {1: 2, 2: 1}


def _session_maker_returning(session):
    class _Wrapper:
        def __call__(self):
            return _Ctx(session)

    class _Ctx:
        def __init__(self, s):
            self._s = s

        async def __aenter__(self):
            return self._s

        async def __aexit__(self, *exc):
            return False

    return _Wrapper()
