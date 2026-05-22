"""One-shot cleanup for issue #71 — backfill raw_match_id and dedupe.

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

Phases:

* **Backfill** — re-extracts the MTGO match UUID from raw ``.dat``
  bodies for rows where ``raw_match_id`` is NULL and updates the
  column in place. Rows whose source bytes have been pruned, or
  whose header didn't contain a parseable UUID, stay NULL.

* **Dedupe** — for each ``(user_id, raw_match_id)`` group with >1
  row, keep the "best" parse (winner-presence first, then game_count,
  then parsed_at desc) and DELETE the rest. Child rows in
  ``parser.games``, ``parser.game_states``, ``parser.game_events``,
  ``parser.game_players``, ``parser.match_archetypes``, and
  ``analytics.card_game_stats`` go via FK cascade.

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
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

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


# ---------------------------------------------------------------------------
# Backfill phase
# ---------------------------------------------------------------------------


async def _backfill_raw_match_ids(
    sm: async_sessionmaker[AsyncSession],
    raw_root: Path,
    *,
    apply: bool,
    max_log_bytes: int | None,
) -> tuple[int, int, int]:
    """Re-extract raw_match_id from archived ``.dat`` bytes.

    Returns ``(scanned, filled, missing_or_unparseable)``.
    """
    async with sm() as session:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT m.id, m.sha256, m.user_id
                      FROM parser.matches m
                     WHERE m.raw_match_id IS NULL
                    """
                )
            )
        ).all()

    scanned = len(rows)
    filled = 0
    missing = 0
    updates: list[dict[str, Any]] = []

    for match_id, sha256, user_id in rows:
        try:
            content = read_raw(sha256, raw_root, max_bytes=max_log_bytes)
        except (RawFileNotFoundError, OSError):
            missing += 1
            continue

        try:
            text_payload = content.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            missing += 1
            continue

        m = _UUID_RE.search(text_payload)
        if m is None:
            missing += 1
            continue

        raw_match_id = m.group(1)
        updates.append({"id": str(match_id), "raw_match_id": raw_match_id, "user_id": int(user_id)})
        filled += 1

    _log.info(
        "backfill: scanned=%d filled=%d missing/unparseable=%d apply=%s",
        scanned,
        filled,
        missing,
        apply,
    )

    if apply and updates:
        async with sm() as session:
            # Apply one at a time — the partial unique index on
            # (raw_match_id, user_id) will raise on collision, which
            # we tolerate (those collisions are exactly what dedupe
            # will resolve next).
            applied = 0
            for u in updates:
                try:
                    await session.execute(
                        text(
                            "UPDATE parser.matches SET raw_match_id = :raw_match_id WHERE id = :id"
                        ),
                        u,
                    )
                    await session.commit()
                    applied += 1
                except Exception:  # noqa: BLE001
                    await session.rollback()
                    _log.debug(
                        "backfill collision id=%s raw_match_id=%s user_id=%s "
                        "(will be resolved by dedupe pass)",
                        u["id"],
                        u["raw_match_id"],
                        u["user_id"],
                    )
            _log.info("backfill: wrote %d rows", applied)

    return scanned, filled, missing


# ---------------------------------------------------------------------------
# Dedupe phase
# ---------------------------------------------------------------------------


def _quality_key(winner: str | None, game_count: int, parsed_at: Any) -> tuple[int, int, Any]:
    """Sort key mirrors :func:`parser_service.persistence._parse_quality_key`.

    A row is "better" when:

    1. It has a non-null winner.
    2. It has a higher game_count.
    3. It was parsed more recently (tiebreak).
    """
    return (1 if winner else 0, int(game_count or 0), parsed_at)


async def _dedupe(
    sm: async_sessionmaker[AsyncSession],
    *,
    apply: bool,
) -> tuple[int, dict[int, dict[str, int]]]:
    """Collapse duplicate ``(user_id, raw_match_id)`` groups.

    Returns ``(rows_deleted, per_user_summary)`` where
    ``per_user_summary[user_id]`` has ``before`` and ``after`` counts
    plus child-cascade counts.
    """
    async with sm() as session:
        rows = (
            await session.execute(
                text(
                    """
                    SELECT m.id, m.user_id, m.raw_match_id, m.winner,
                           m.game_count, m.parsed_at
                      FROM parser.matches m
                     WHERE m.raw_match_id IS NOT NULL
                  ORDER BY m.user_id, m.raw_match_id, m.parsed_at DESC
                    """
                )
            )
        ).all()

    groups: dict[tuple[int, str], list[Any]] = defaultdict(list)
    for row in rows:
        groups[(int(row.user_id), str(row.raw_match_id))].append(row)

    delete_ids: list[str] = []
    per_user: dict[int, dict[str, int]] = defaultdict(
        lambda: {"before": 0, "after": 0, "deleted": 0}
    )

    for (user_id, _rmid), group in groups.items():
        per_user[user_id]["before"] += len(group)
        if len(group) == 1:
            per_user[user_id]["after"] += 1
            continue
        # Keep the best.
        keeper = max(group, key=lambda r: _quality_key(r.winner, r.game_count, r.parsed_at))
        per_user[user_id]["after"] += 1
        for r in group:
            if r.id == keeper.id:
                continue
            delete_ids.append(str(r.id))
            per_user[user_id]["deleted"] += 1

    # Also include users who had no duplicates at all in the summary —
    # easier for the operator to see scale of the operation.
    for (user_id, _rmid), group in groups.items():
        if len(group) == 1:
            per_user.setdefault(user_id, {"before": 0, "after": 0, "deleted": 0})

    if not delete_ids:
        _log.info("dedupe: no duplicates found")
        return 0, dict(per_user)

    # Child-cascade preview (best-effort across both schemas).
    try:
        async with sm() as session:
            child_row = (await session.execute(_CHILD_COUNT_SQL, {"ids": delete_ids})).one_or_none()
    except Exception:  # noqa: BLE001
        child_row = None

    if child_row is not None:
        _log.info(
            "dedupe: will delete %d match rows + cascade "
            "games=%d game_players=%d game_events=%d game_states=%d "
            "match_archetypes=%d card_game_stats=%d",
            len(delete_ids),
            int(child_row.games or 0),
            int(child_row.game_players or 0),
            int(child_row.game_events or 0),
            int(child_row.game_states or 0),
            int(child_row.match_archetypes or 0),
            int(child_row.card_game_stats or 0),
        )
    else:
        _log.info("dedupe: will delete %d match rows (cascade count unavailable)", len(delete_ids))

    if not apply:
        return len(delete_ids), dict(per_user)

    # Apply the deletes. analytics.card_game_stats has no FK to
    # parser.matches.id, so delete it explicitly first; everything
    # under parser.games cascades.
    async with sm() as session:
        await session.execute(
            text("DELETE FROM analytics.card_game_stats WHERE match_id = ANY(:ids)"),
            {"ids": delete_ids},
        )
        deleted_row = await session.execute(
            text("DELETE FROM parser.matches WHERE id = ANY(:ids) RETURNING id"),
            {"ids": delete_ids},
        )
        deleted = len(deleted_row.all())
        await session.commit()

    _log.info("dedupe: deleted %d match rows", deleted)
    return deleted, dict(per_user)


# ---------------------------------------------------------------------------
# Cache flush — best-effort
# ---------------------------------------------------------------------------


async def _flush_analytics_caches(
    sm: async_sessionmaker[AsyncSession],
    affected_user_ids: list[int],
    *,
    apply: bool,
) -> None:
    """Try to invalidate per-user analytics summary keys in Redis.

    The exact key shape lives in the analytics service; this script
    runs in the parser container and may not have an exact mirror, so
    we attempt a best-effort SCAN/DEL by user_id substring and log a
    warning if anything looks off.
    """
    if not affected_user_ids:
        return

    try:
        import redis.asyncio as redis  # local import — optional dep at runtime
    except ImportError:
        _log.warning(
            "redis client unavailable — cannot flush analytics caches. "
            "Operator: flush per-user summary/by-format keys manually."
        )
        return

    try:
        settings = get_settings()
        client = redis.from_url(settings.redis_url)
    except Exception:  # noqa: BLE001
        _log.warning(
            "could not connect to redis (redis_url=%s) — flush per-user "
            "analytics:summary:* and analytics:by-format:* keys manually",
            getattr(get_settings(), "redis_url", "<unset>"),
        )
        return

    patterns = [
        "analytics:summary:user:*",
        "analytics:by-format:user:*",
        "analytics:stats:user:*",
    ]
    matched: list[bytes] = []
    try:
        for pattern in patterns:
            async for key in client.scan_iter(match=pattern, count=200):
                matched.append(key)
        if not matched:
            _log.info(
                "cache flush: no analytics:* keys matched standard patterns. "
                "If the dashboard still shows stale totals after this run, "
                "operator should flush analytics keys manually."
            )
        elif apply:
            await client.delete(*matched)
            _log.info("cache flush: deleted %d analytics keys", len(matched))
        else:
            _log.info("cache flush: would delete %d analytics keys", len(matched))
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

    scanned, filled, missing = await _backfill_raw_match_ids(
        sm,
        settings.parser_raw_path,
        apply=apply,
        max_log_bytes=settings.parser_max_log_bytes,
    )

    deleted, per_user = await _dedupe(sm, apply=apply)

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
        "cleanup #71 done mode=%s scanned=%d filled=%d "
        "raw_match_id_missing=%d duplicate_rows_deleted=%d affected_users=%d",
        mode,
        scanned,
        filled,
        missing,
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
        help="Actually perform the backfill + dedupe + cache flush.",
    )
    args = parser.parse_args(argv)
    apply = bool(args.apply)
    return asyncio.run(_run(apply=apply))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
