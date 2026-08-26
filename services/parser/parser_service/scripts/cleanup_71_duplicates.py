"""One-shot cleanup for issue #71 — group by logical identity and dedupe.

The agent's 5-second stability gate fires during natural lulls in
play, so MTGO's growing ``Match_GameLog_<uuid>.dat`` was shipped to
the server multiple times during a single match. Each shipment had a
distinct ``sha256`` (different bytes) so dedup at every layer let
them through, producing many ``parser.matches`` rows for one logical
match.

Run order (operator):

1. Deploy v0.9.8 — adds ``raw_match_id`` column, partial unique index,
   and the new persistence-time identity logic.
2. Then run this script inside the parser container::

       python -m parser_service.scripts.cleanup_71_duplicates --dry-run
       python -m parser_service.scripts.cleanup_71_duplicates --apply

   Dry-run is the default and only prints what it *would* do.

Algorithm (Codex P1):

* **Discover (read-only).** For every ``parser.matches`` row we
  compute the *would-be* ``raw_match_id``: the stored value if set,
  otherwise the ``$<uuid>`` extracted from the archived object body.
  Rows whose source bytes are pruned or whose header doesn't contain
  a parseable UUID are reported and skipped (we can't identify what
  logical match they belong to).

* **Apply.** Group by ``(user_id, computed_raw_match_id)``.
  - Groups of >1: pick the "best" parse (winner-presence first, then
    game_count, then parsed_at desc), DELETE the rest. Child rows in
    ``parser.games``, ``parser.game_states``, ``parser.game_events``,
    ``parser.game_players``, ``parser.match_archetypes``, and
    ``analytics.card_game_stats`` go via FK cascade.
  - After deletes, UPDATE the surviving (or singleton) row to set
    ``raw_match_id`` if it was NULL. This UPDATE is safe now because
    the collision rows have been removed.

  Doing deletes first is what fixes the collision-victims bug: in the
  previous "backfill first, dedupe second" shape, two rows fighting
  for the same ``(raw_match_id, user_id)`` would race the backfill
  UPDATE, the loser stayed NULL, and the dedupe phase
  (``WHERE raw_match_id IS NOT NULL``) never noticed it as a
  duplicate — so it survived as a zombie with stale match counts.

* **Cache flush** — best-effort flush of per-user analytics summary
  keys in Redis so stale dashboards re-compute on next view.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import re
import sys
from collections import defaultdict
from typing import Any, NamedTuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from common.storage import ObjectStorageError, ObjectStore, get_object_store
from parser_service.db import get_sessionmaker
from parser_service.settings import get_settings
from parser_service.storage import RawFileNotFoundError, read_raw

_log = logging.getLogger("parser.cleanup_71")

# Same pattern the live parser uses (see parser_service.parsing.parser).
_UUID_RE = re.compile(r"\$([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

# Children that hang off a match row directly. CASCADE FKs handle
# everything reachable from games (game_states, game_events,
# game_players) — we only need to count them for the operator log.
_CHILD_COUNT_SQL = text(
    """
    SELECT
      (SELECT COUNT(*) FROM parser.games WHERE match_id = ANY(:ids)) AS games,
      (SELECT COUNT(*) FROM parser.game_players gp
         JOIN parser.games g ON g.id = gp.game_id
        WHERE g.match_id = ANY(:ids)) AS game_players,
      (SELECT COUNT(*) FROM parser.game_events ev
         JOIN parser.games g ON g.id = ev.game_id
        WHERE g.match_id = ANY(:ids)) AS game_events,
      (SELECT COUNT(*) FROM parser.game_states gs
         JOIN parser.games g ON g.id = gs.game_id
        WHERE g.match_id = ANY(:ids)) AS game_states,
      (SELECT COUNT(*) FROM parser.match_archetypes
        WHERE match_id = ANY(:ids)) AS match_archetypes,
      (SELECT COUNT(*) FROM analytics.card_game_stats
        WHERE match_id = ANY(:ids)) AS card_game_stats
    """
)


def _quality_key(winner: str | None, game_count: int, parsed_at: Any) -> tuple[int, int, Any]:
    """Sort key mirrors :func:`parser_service.persistence._parse_quality_key`.

    A row is "better" when:

    1. It has a non-null winner.
    2. It has a higher game_count.
    3. It was parsed more recently (tiebreak).
    """
    return (1 if winner else 0, int(game_count or 0), parsed_at)


class _MatchRow(NamedTuple):
    id: str
    user_id: int
    sha256: str
    raw_match_id: str | None
    winner: str | None
    game_count: int
    parsed_at: Any


# ---------------------------------------------------------------------------
# Discovery phase — compute the logical identity for every match row
# ---------------------------------------------------------------------------


async def compute_groups(
    rows: list[_MatchRow],
    *,
    extract_uuid: Any,
) -> tuple[dict[tuple[int, str], list[_MatchRow]], int]:
    """Group rows by ``(user_id, computed_raw_match_id)``.

    Accepts an async ``extract_uuid(sha256) -> str | None`` callable so
    the test suite can drive it without an object store.

    Returns ``(groups, unidentifiable_count)``. ``unidentifiable_count``
    is the number of rows we had to skip because they had no
    ``raw_match_id`` set AND no parseable UUID in their archived bytes.
    """
    groups: dict[tuple[int, str], list[_MatchRow]] = defaultdict(list)
    unidentifiable = 0
    for row in rows:
        if row.raw_match_id is not None:
            computed = row.raw_match_id
        else:
            computed = await extract_uuid(row.sha256)
            if computed is None:
                unidentifiable += 1
                continue
        groups[(int(row.user_id), str(computed))].append(row)
    return groups, unidentifiable


async def _load_match_rows(sm: async_sessionmaker[AsyncSession]) -> list[_MatchRow]:
    async with sm() as session:
        result = await session.execute(
            text(
                """
                SELECT m.id, m.user_id, m.sha256, m.raw_match_id,
                       m.winner, m.game_count, m.parsed_at
                  FROM parser.matches m
              ORDER BY m.user_id, m.parsed_at DESC
                """
            )
        )
        return [
            _MatchRow(
                id=str(r.id),
                user_id=int(r.user_id),
                sha256=str(r.sha256),
                raw_match_id=str(r.raw_match_id) if r.raw_match_id is not None else None,
                winner=r.winner,
                game_count=int(r.game_count or 0),
                parsed_at=r.parsed_at,
            )
            for r in result.all()
        ]


def _make_uuid_extractor(store: ObjectStore, key_prefix: str, max_log_bytes: int | None):
    """Build the ``extract_uuid`` callable used during discovery."""

    async def _extract(sha256: str) -> str | None:
        try:
            content = await read_raw(store, sha256, key_prefix=key_prefix, max_bytes=max_log_bytes)
        except (RawFileNotFoundError, ObjectStorageError, OSError):
            return None
        try:
            text_payload = content.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return None
        m = _UUID_RE.search(text_payload)
        if m is None:
            return None
        return m.group(1)

    return _extract


# ---------------------------------------------------------------------------
# Apply phase — deletes first, then backfill the survivors
# ---------------------------------------------------------------------------


class _Plan(NamedTuple):
    """The computed plan for what to delete and what to backfill."""

    # Rows to DELETE. Each entry is (user_id, row_id) so we can
    # report per-user counts cleanly.
    deletes: list[tuple[int, str]]
    # Rows whose ``raw_match_id`` is NULL but should be set after the
    # deletes complete. Each entry is (row_id, raw_match_id, user_id).
    backfills: list[tuple[str, str, int]]
    # Per-user before/after/deleted counts. Includes users with no
    # changes so the summary shows scale.
    per_user: dict[int, dict[str, int]]


def plan_actions(groups: dict[tuple[int, str], list[_MatchRow]]) -> _Plan:
    """Decide what to delete and what to backfill from the discovered groups."""
    deletes: list[tuple[int, str]] = []
    backfills: list[tuple[str, str, int]] = []
    per_user: dict[int, dict[str, int]] = defaultdict(
        lambda: {"before": 0, "after": 0, "deleted": 0}
    )

    for (user_id, computed_raw_match_id), group in groups.items():
        per_user[user_id]["before"] += len(group)
        per_user[user_id]["after"] += 1

        if len(group) == 1:
            (only,) = group
            if only.raw_match_id is None:
                # Singleton with no raw_match_id — needs the backfill
                # update so future parses key on raw_match_id.
                backfills.append((only.id, computed_raw_match_id, user_id))
            continue

        # >1: keep the best, delete the rest.
        keeper = max(
            group,
            key=lambda r: _quality_key(r.winner, r.game_count, r.parsed_at),
        )
        if keeper.raw_match_id is None:
            backfills.append((keeper.id, computed_raw_match_id, user_id))
        for r in group:
            if r.id == keeper.id:
                continue
            deletes.append((user_id, r.id))
            per_user[user_id]["deleted"] += 1

    return _Plan(deletes=deletes, backfills=backfills, per_user=dict(per_user))


async def _apply_deletes(
    sm: async_sessionmaker[AsyncSession],
    delete_ids: list[str],
) -> int:
    """Run the deletes and return the number of match rows removed."""
    async with sm() as session:
        # analytics.card_game_stats has no FK to parser.matches.id, so
        # delete it explicitly first; everything else cascades.
        await session.execute(
            text("DELETE FROM analytics.card_game_stats WHERE match_id = ANY(:ids)"),
            {"ids": delete_ids},
        )
        result = await session.execute(
            text("DELETE FROM parser.matches WHERE id = ANY(:ids) RETURNING id"),
            {"ids": delete_ids},
        )
        deleted = len(result.all())
        await session.commit()
    return deleted


async def _apply_backfills(
    sm: async_sessionmaker[AsyncSession],
    backfills: list[tuple[str, str, int]],
) -> int:
    """Set ``raw_match_id`` on rows that had it NULL. Returns rows updated."""
    if not backfills:
        return 0
    async with sm() as session:
        applied = 0
        for row_id, raw_match_id, user_id in backfills:
            try:
                await session.execute(
                    text(
                        "UPDATE parser.matches "
                        "SET raw_match_id = :raw_match_id "
                        "WHERE id = :id "
                        "  AND raw_match_id IS NULL"
                    ),
                    {"id": row_id, "raw_match_id": raw_match_id},
                )
                await session.commit()
                applied += 1
            except Exception:  # noqa: BLE001
                # Shouldn't happen now that the duplicates are gone,
                # but if it does, log and keep going — better to
                # backfill 999/1000 rows than abort the whole pass.
                await session.rollback()
                _log.warning(
                    "backfill failed unexpectedly id=%s raw_match_id=%s user_id=%s",
                    row_id,
                    raw_match_id,
                    user_id,
                )
        return applied


async def _run_cleanup(
    sm: async_sessionmaker[AsyncSession],
    store: ObjectStore,
    *,
    apply: bool,
    max_log_bytes: int | None,
    key_prefix: str = "raw",
) -> tuple[int, int, int, dict[int, dict[str, int]]]:
    """End-to-end discover + plan + apply. Returns telemetry.

    ``(scanned, unidentifiable, deleted, per_user)``.
    """
    rows = await _load_match_rows(sm)
    scanned = len(rows)
    extractor = _make_uuid_extractor(store, key_prefix, max_log_bytes)
    groups, unidentifiable = await compute_groups(rows, extract_uuid=extractor)
    plan = plan_actions(groups)

    delete_ids = [row_id for _uid, row_id in plan.deletes]

    _log.info(
        "discover: scanned=%d groups=%d unidentifiable=%d will_delete=%d will_backfill=%d",
        scanned,
        len(groups),
        unidentifiable,
        len(delete_ids),
        len(plan.backfills),
    )

    if delete_ids:
        try:
            async with sm() as session:
                child_row = (
                    await session.execute(_CHILD_COUNT_SQL, {"ids": delete_ids})
                ).one_or_none()
        except Exception:  # noqa: BLE001
            child_row = None
        if child_row is not None:
            _log.info(
                "cascade preview: matches=%d games=%d game_players=%d "
                "game_events=%d game_states=%d match_archetypes=%d card_game_stats=%d",
                len(delete_ids),
                int(child_row.games or 0),
                int(child_row.game_players or 0),
                int(child_row.game_events or 0),
                int(child_row.game_states or 0),
                int(child_row.match_archetypes or 0),
                int(child_row.card_game_stats or 0),
            )
        else:
            _log.info(
                "cascade preview: matches=%d (child counts unavailable)",
                len(delete_ids),
            )

    if not apply:
        return scanned, unidentifiable, 0, plan.per_user

    deleted = await _apply_deletes(sm, delete_ids) if delete_ids else 0
    backfilled = await _apply_backfills(sm, plan.backfills)
    _log.info(
        "applied: deleted=%d backfilled=%d (of %d planned)",
        deleted,
        backfilled,
        len(plan.backfills),
    )
    return scanned, unidentifiable, deleted, plan.per_user


# ---------------------------------------------------------------------------
# Cache flush — best-effort
# ---------------------------------------------------------------------------


async def _flush_analytics_caches(
    sm: async_sessionmaker[AsyncSession],
    affected_user_ids: list[int],
    *,
    apply: bool,
) -> None:
    """Invalidate per-user analytics cache keys in Redis.

    Uses :func:`common.cache.invalidate_user`, which deletes everything
    matching ``da:stats:{user_id}:*`` — the namespace the analytics
    service actually writes (see ``common/cache.py``). Best-effort: any
    Redis failure is logged but does not abort the cleanup run.
    """
    if not affected_user_ids:
        return

    try:
        import redis.asyncio as redis  # local import — optional dep at runtime
    except ImportError:
        _log.warning(
            "redis client unavailable — cannot flush analytics caches. "
            "Operator: flush per-user `da:stats:{user_id}:*` keys manually."
        )
        return

    try:
        settings = get_settings()
        client = redis.from_url(settings.redis_url)
    except Exception:  # noqa: BLE001
        _log.warning(
            "could not connect to redis (redis_url=%s) — flush per-user "
            "`da:stats:{user_id}:*` keys manually",
            getattr(get_settings(), "redis_url", "<unset>"),
        )
        return

    if not apply:
        _log.info(
            "cache flush: would invalidate da:stats:{user_id}:* for %d user(s)",
            len(affected_user_ids),
        )
        with contextlib.suppress(Exception):
            await client.aclose()
        return

    from common.cache import invalidate_user

    total = 0
    try:
        for user_id in affected_user_ids:
            deleted = await invalidate_user(client, user_id)
            _log.info("cache flush: user_id=%s deleted=%d keys", user_id, deleted)
            total += deleted
        _log.info(
            "cache flush: deleted %d da:stats keys across %d user(s)",
            total,
            len(affected_user_ids),
        )
    finally:
        with contextlib.suppress(Exception):
            await client.aclose()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


async def _run(apply: bool) -> int:
    _configure_logging()
    settings = get_settings()
    sm = get_sessionmaker()

    mode = "APPLY" if apply else "DRY-RUN"
    _log.info("cleanup #71 starting mode=%s", mode)

    scanned, unidentifiable, deleted, per_user = await _run_cleanup(
        sm,
        get_object_store(settings.s3_config()),
        apply=apply,
        max_log_bytes=settings.parser_max_log_bytes,
        key_prefix=settings.s3_key_prefix,
    )

    affected_users = sorted(uid for uid, stats in per_user.items() if stats.get("deleted", 0) > 0)
    if affected_users:
        _log.info("per-user summary (only users with duplicates shown):")
        for uid in affected_users:
            s = per_user[uid]
            _log.info(
                "  user_id=%s before=%d after=%d deleted=%d",
                uid,
                s["before"],
                s["after"],
                s["deleted"],
            )

    await _flush_analytics_caches(sm, affected_users, apply=apply)

    _log.info(
        "cleanup #71 done mode=%s scanned=%d unidentifiable=%d "
        "duplicate_rows_deleted=%d affected_users=%d",
        mode,
        scanned,
        unidentifiable,
        deleted,
        len(affected_users),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m parser_service.scripts.cleanup_71_duplicates",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Print what would be done without mutating the database (default).",
    )
    grp.add_argument(
        "--apply",
        action="store_true",
        help="Actually perform the dedupe + backfill + cache flush.",
    )
    args = parser.parse_args(argv)
    apply = bool(args.apply)
    return asyncio.run(_run(apply=apply))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
