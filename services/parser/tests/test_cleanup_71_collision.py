"""Tests for cleanup_71_duplicates collision-victim handling (Codex P1).

The previous shape of this script ran a backfill pass that suppressed
unique-violation collisions when setting ``raw_match_id``. The
loser-on-collision rows stayed at ``raw_match_id = NULL``, and the
dedupe pass then queried ``WHERE raw_match_id IS NOT NULL`` and never
saw them — they survived as zombie duplicates with stale match counts
hanging around the per-user dashboards.

The fix restructures into discover → dedupe-first → backfill-after.
These tests cover both halves:

* ``plan_actions`` makes the right delete/backfill decisions purely
  from in-memory grouped rows (no DB needed).
* ``_run_cleanup`` against a real Postgres exercises the full path,
  including the collision scenario the previous shape regressed on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from parser_service.models import Match
from parser_service.scripts.cleanup_71_duplicates import (
    _MatchRow,
    _run_cleanup,
    compute_groups,
    plan_actions,
)
from sqlalchemy import select

# ---------------------------------------------------------------------------
# Unit tests — plan_actions on synthetic groups
# ---------------------------------------------------------------------------


def _row(
    *,
    rid: str,
    user_id: int = 1,
    sha256: str = "x" * 64,
    raw_match_id: str | None = None,
    winner: str | None = None,
    game_count: int = 0,
    parsed_at: datetime | None = None,
) -> _MatchRow:
    return _MatchRow(
        id=rid,
        user_id=user_id,
        sha256=sha256,
        raw_match_id=raw_match_id,
        winner=winner,
        game_count=game_count,
        parsed_at=parsed_at or datetime.now(UTC),
    )


class TestComputeGroups:
    def test_existing_raw_match_id_used_verbatim(self) -> None:
        rows = [_row(rid="r1", raw_match_id="UUID-A")]
        groups, unident = compute_groups(rows, extract_uuid=lambda _sha: None)
        assert unident == 0
        assert groups == {(1, "UUID-A"): rows}

    def test_null_raw_match_id_extracted_from_bytes(self) -> None:
        rows = [_row(rid="r1", raw_match_id=None, sha256="abc")]
        groups, unident = compute_groups(
            rows,
            extract_uuid=lambda sha: "UUID-FROM-BYTES" if sha == "abc" else None,
        )
        assert unident == 0
        assert groups == {(1, "UUID-FROM-BYTES"): rows}

    def test_unparseable_rows_skipped(self) -> None:
        rows = [
            _row(rid="r1", raw_match_id=None, sha256="lost"),
            _row(rid="r2", raw_match_id="UUID-B"),
        ]
        groups, unident = compute_groups(rows, extract_uuid=lambda _sha: None)
        assert unident == 1
        assert (1, "UUID-B") in groups
        assert all((1, "lost") not in k for k in groups)

    def test_multiple_users_grouped_separately(self) -> None:
        rows = [
            _row(rid="r1", user_id=1, raw_match_id="UUID-X"),
            _row(rid="r2", user_id=2, raw_match_id="UUID-X"),
        ]
        groups, _ = compute_groups(rows, extract_uuid=lambda _sha: None)
        assert (1, "UUID-X") in groups
        assert (2, "UUID-X") in groups
        assert len(groups[(1, "UUID-X")]) == 1
        assert len(groups[(2, "UUID-X")]) == 1


class TestPlanActions:
    def test_three_collision_victims_one_survives(self) -> None:
        """Three rows for the same logical match, all raw_match_id=NULL.
        One survives, the other two are queued for deletion, and the
        survivor is queued for raw_match_id backfill — this is the
        zombie-duplicate scenario the previous backfill-first shape
        left behind."""
        now = datetime.now(UTC)
        group = [
            _row(rid="r1", winner=None, game_count=1, parsed_at=now),
            _row(rid="r2", winner="alice", game_count=2, parsed_at=now),  # best
            _row(rid="r3", winner=None, game_count=3, parsed_at=now),
        ]
        groups = {(1, "UUID-Y"): group}
        plan = plan_actions(groups)

        assert {row_id for _uid, row_id in plan.deletes} == {"r1", "r3"}
        # Winner has its raw_match_id backfilled.
        assert plan.backfills == [("r2", "UUID-Y", 1)]
        assert plan.per_user[1]["before"] == 3
        assert plan.per_user[1]["after"] == 1
        assert plan.per_user[1]["deleted"] == 2

    def test_singleton_with_null_raw_match_id_gets_backfilled(self) -> None:
        rows = [_row(rid="r1", raw_match_id=None)]
        plan = plan_actions({(1, "UUID-Z"): rows})
        assert plan.deletes == []
        assert plan.backfills == [("r1", "UUID-Z", 1)]

    def test_singleton_already_keyed_no_op(self) -> None:
        rows = [_row(rid="r1", raw_match_id="UUID-Z")]
        plan = plan_actions({(1, "UUID-Z"): rows})
        assert plan.deletes == []
        assert plan.backfills == []

    def test_keeper_already_keyed_only_losers_deleted(self) -> None:
        """If the winner already has raw_match_id set, only the losers
        are deleted; no backfill is queued for the survivor."""
        now = datetime.now(UTC)
        group = [
            _row(rid="r1", raw_match_id="UUID-K", winner="alice", game_count=2, parsed_at=now),
            _row(rid="r2", raw_match_id=None, winner=None, game_count=1, parsed_at=now),
        ]
        plan = plan_actions({(1, "UUID-K"): group})
        assert {row_id for _uid, row_id in plan.deletes} == {"r2"}
        assert plan.backfills == []


# ---------------------------------------------------------------------------
# Integration test — full cleanup against a real Postgres
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_eliminates_zombie_duplicates(parser_session, tmp_path) -> None:
    """End-to-end exercise of the collision-victim path.

    The production scenario: three matches rows exist for the same
    logical match, each with a *different* sha256 (MTGO appended bytes
    between snapshots) but the same parseable UUID in their raw
    payloads. All three have ``raw_match_id=NULL``.

    After ``--apply``, exactly one row survives with ``raw_match_id``
    set, and the other two are gone (with their children cascaded
    out). Under the previous "backfill first, dedupe by raw_match_id
    second" shape, two of these rows survived as zombies because the
    backfill collision left them with NULL raw_match_id, hiding them
    from the dedupe pass.
    """
    target_uuid = "feedf00d-1111-2222-3333-444444444444"
    now = datetime.now(UTC)
    shas = ["a" * 64, "b" * 64, "c" * 64]

    rows = [
        Match(
            id=uuid.uuid4(),
            sha256=shas[0],
            user_id=1,
            raw_match_id=None,
            players=["alice", "bob"],
            winner=None,
            game_count=1,
            parsed_at=now,
        ),
        Match(
            id=uuid.uuid4(),
            sha256=shas[1],
            user_id=1,
            raw_match_id=None,
            players=["alice", "bob"],
            winner="alice",  # best parse — should be kept
            game_count=2,
            parsed_at=now,
        ),
        Match(
            id=uuid.uuid4(),
            sha256=shas[2],
            user_id=1,
            raw_match_id=None,
            players=["alice", "bob"],
            winner=None,
            game_count=3,
            parsed_at=now,
        ),
    ]
    keeper_id = rows[1].id
    parser_session.add_all(rows)
    await parser_session.commit()

    # Pre-stage the raw bytes so the UUID extractor finds the match
    # UUID for each sha. Layout mirrors what ingest writes:
    # <root>/<sha[0:2]>/<sha[2:4]>/<sha>.dat
    for sha in shas:
        shard = tmp_path / sha[0:2] / sha[2:4]
        shard.mkdir(parents=True)
        (shard / f"{sha}.dat").write_bytes(f"prefix ${target_uuid} body".encode())

    sm = _session_maker_returning(parser_session)

    scanned, unident, deleted, per_user = await _run_cleanup(
        sm,
        Path(tmp_path),
        apply=True,
        max_log_bytes=None,
    )

    assert scanned == 3
    assert unident == 0
    assert deleted == 2
    assert per_user[1]["before"] == 3
    assert per_user[1]["after"] == 1
    assert per_user[1]["deleted"] == 2

    # Drop ORM cache so the survivor row re-loads from the DB rather
    # than from the identity map (the cleanup script writes via raw
    # SQL, bypassing the ORM).
    parser_session.expire_all()

    survivors = (
        (await parser_session.execute(select(Match).where(Match.user_id == 1))).scalars().all()
    )
    assert len(survivors) == 1
    assert survivors[0].id == keeper_id
    assert survivors[0].raw_match_id == target_uuid
    assert survivors[0].winner == "alice"


@pytest.mark.asyncio
async def test_dry_run_changes_nothing(parser_session, tmp_path) -> None:
    """``--dry-run`` reports what *would* happen but mutates nothing."""
    target_uuid = "00112233-4455-6677-8899-aabbccddeeff"
    shas = ["d" * 64, "e" * 64]

    parser_session.add_all(
        [
            Match(
                id=uuid.uuid4(),
                sha256=shas[0],
                user_id=7,
                raw_match_id=None,
                players=["a", "b"],
                winner="a",
                game_count=2,
            ),
            Match(
                id=uuid.uuid4(),
                sha256=shas[1],
                user_id=7,
                raw_match_id=None,
                players=["a", "b"],
                winner=None,
                game_count=1,
            ),
        ]
    )
    await parser_session.commit()

    for sha in shas:
        shard = tmp_path / sha[0:2] / sha[2:4]
        shard.mkdir(parents=True)
        (shard / f"{sha}.dat").write_bytes(f"prefix ${target_uuid} suffix".encode())

    sm = _session_maker_returning(parser_session)

    scanned, _unident, deleted, _per_user = await _run_cleanup(
        sm,
        Path(tmp_path),
        apply=False,
        max_log_bytes=None,
    )
    assert scanned == 2
    assert deleted == 0

    rows = (await parser_session.execute(select(Match).where(Match.user_id == 7))).scalars().all()
    assert len(rows) == 2
    assert all(r.raw_match_id is None for r in rows)


def _session_maker_returning(session):
    """Adapter that hands the real cleanup script our test session.

    The script expects an ``async_sessionmaker`` it can call ``sm()``
    against; we wrap the test's session in a no-op context manager so
    each ``async with sm() as s`` yields the same session. Commits
    inside the script land on the same transaction the fixture
    truncates between tests.
    """

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


# ---------------------------------------------------------------------------
# Cache invalidation — `da:stats:{user_id}:*` namespace
# ---------------------------------------------------------------------------


class _StubRedis:
    """Minimal stand-in for redis.asyncio.Redis used by the cache flush."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def _install_redis_and_settings_stubs(monkeypatch) -> _StubRedis:
    """Patch `redis.asyncio.from_url` + `get_settings` for cache-flush tests.

    Avoids needing the parser service's full env-var stack
    (database_url, jwt_public_key_path, etc.) just to exercise the flush.
    """
    stub_client = _StubRedis()

    import redis.asyncio as redis_asyncio

    monkeypatch.setattr(redis_asyncio, "from_url", lambda _url: stub_client)

    from parser_service.scripts import cleanup_71_duplicates as mod

    monkeypatch.setattr(mod, "get_settings", lambda: type("S", (), {"redis_url": "redis://stub"})())
    return stub_client


@pytest.mark.asyncio
async def test_flush_calls_invalidate_user_per_affected_user(monkeypatch) -> None:
    """`--apply` path calls `invalidate_user` once per affected user."""
    from parser_service.scripts import cleanup_71_duplicates as mod

    stub_client = _install_redis_and_settings_stubs(monkeypatch)

    calls: list[tuple[object, int]] = []

    async def _fake_invalidate(client, user_id: int) -> int:
        calls.append((client, user_id))
        return 5

    import common.cache

    monkeypatch.setattr(common.cache, "invalidate_user", _fake_invalidate)

    await mod._flush_analytics_caches(None, [2, 4, 8], apply=True)

    assert [uid for _c, uid in calls] == [2, 4, 8]
    assert all(c is stub_client for c, _uid in calls)
    assert stub_client.closed is True


@pytest.mark.asyncio
async def test_flush_dry_run_does_not_invalidate(monkeypatch) -> None:
    """`--dry-run` path must not call `invalidate_user` (no Redis writes)."""
    from parser_service.scripts import cleanup_71_duplicates as mod

    stub_client = _install_redis_and_settings_stubs(monkeypatch)

    calls: list[int] = []

    async def _fake_invalidate(_client, user_id: int) -> int:
        calls.append(user_id)
        return 0

    import common.cache

    monkeypatch.setattr(common.cache, "invalidate_user", _fake_invalidate)

    await mod._flush_analytics_caches(None, [2, 4], apply=False)

    assert calls == []
    assert stub_client.closed is True
