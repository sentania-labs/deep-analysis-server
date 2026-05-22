"""One-shot backfill — flag legacy partial parses as pending_review.

Pre-v0.9.8, the consumer either dropped partial parses (post-#75) or
persisted them as winner-less "draw husks" (pre-#75). v0.9.8 introduces
the holding pen: partial parses now land with
``review_status='pending_review'`` so an admin can decide. This script
walks existing ``parser.matches`` rows and applies the same verdict to
legacy data the consumer can't see anymore.

Run order (operator):

1. Deploy v0.9.8 — adds ``parser.matches.review_status`` (alembic 025)
   and the new consumer + persistence behavior.
2. Then run this script inside the parser container::

       python -m parser_service.scripts.backfill_holding_pen --dry-run
       python -m parser_service.scripts.backfill_holding_pen --apply

   Dry-run is the default and only prints what it *would* do.

Identification rule (mirrors :func:`consumer._is_partial_parse`):

A row is queued for flagging when **all** of the following hold:

* ``review_status IS NULL`` (already flagged rows are left alone).
* ``winner IS NULL`` on ``parser.matches``.
* No row in ``parser.games`` for this ``match_id`` has a non-null
  ``winner`` (i.e. no game has a resolved per-game winner).

A real Magic draw — match winner null but at least one ``parser.games``
row has a winner — is preserved as user-visible. Empty rows with no
games at all are also flagged; the consumer drops empty *new* parses,
but legacy empties already exist in the DB and the admin should see
them too.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys
from collections import defaultdict
from typing import NamedTuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from parser_service.db import get_sessionmaker
from parser_service.settings import get_settings

_log = logging.getLogger("parser.backfill_holding_pen")


class _Candidate(NamedTuple):
    """A row identified as a holding-pen candidate."""

    match_id: str
    user_id: int


# Identifies "would flag" rows: review_status NULL + match-level winner
# NULL + no per-game winner. ``LEFT JOIN ... GROUP BY ... HAVING
# BOOL_OR(g.winner IS NOT NULL) IS NOT TRUE`` evaluates to true both for
# matches with no games at all and matches whose games all have NULL
# winners — the same union the consumer's _is_empty_parse OR
# _is_partial_parse catches on the live path.
_CANDIDATE_SQL = text(
    """
    SELECT m.id, m.user_id
      FROM parser.matches m
      LEFT JOIN parser.games g ON g.match_id = m.id
     WHERE m.review_status IS NULL
       AND m.winner IS NULL
     GROUP BY m.id, m.user_id
    HAVING BOOL_OR(g.winner IS NOT NULL) IS NOT TRUE
    """
)


async def discover_candidates(
    sm: async_sessionmaker[AsyncSession],
) -> list[_Candidate]:
    """Return all rows that would be flagged as pending_review.

    Pure-read query — safe to call from --dry-run.
    """
    async with sm() as session:
        rows = (await session.execute(_CANDIDATE_SQL)).all()
    return [_Candidate(match_id=str(r[0]), user_id=int(r[1])) for r in rows]


async def apply_flags(
    sm: async_sessionmaker[AsyncSession],
    candidates: list[_Candidate],
) -> int:
    """Set ``review_status='pending_review'`` on the given matches.

    Returns the number of rows actually updated. The WHERE clause
    re-checks ``review_status IS NULL`` so a concurrent admin verdict
    between discover and apply is preserved.
    """
    if not candidates:
        return 0
    ids = [c.match_id for c in candidates]
    async with sm() as session:
        result = await session.execute(
            text(
                "UPDATE parser.matches "
                "SET review_status = 'pending_review' "
                "WHERE id = ANY(:ids) AND review_status IS NULL "
                "RETURNING id"
            ),
            {"ids": ids},
        )
        updated = len(result.all())
        await session.commit()
    return updated


def per_user_counts(candidates: list[_Candidate]) -> dict[int, int]:
    """Aggregate candidates by user_id for operator-friendly logging."""
    counts: dict[int, int] = defaultdict(int)
    for c in candidates:
        counts[c.user_id] += 1
    return dict(counts)


async def _flush_analytics_caches(
    affected_user_ids: list[int],
    *,
    apply: bool,
) -> None:
    """Best-effort: invalidate per-user analytics summary keys.

    Mirrors :func:`cleanup_71_duplicates._flush_analytics_caches`. The
    backfill changes what shows up on the user dashboard for every
    affected user, so caches must be flushed for the change to be
    visible without waiting for the cached value to expire.
    """
    if not affected_user_ids:
        return
    try:
        import redis.asyncio as redis
    except ImportError:
        _log.warning(
            "redis client unavailable — cannot flush analytics caches. "
            "Operator: flush per-user analytics:* keys manually."
        )
        return

    try:
        settings = get_settings()
        client = redis.from_url(settings.redis_url)
    except Exception:  # noqa: BLE001
        _log.warning(
            "could not connect to redis — flush analytics:summary:user:* "
            "and analytics:by-format:user:* keys manually",
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
            _log.info("cache flush: no analytics keys matched standard patterns")
        elif apply:
            await client.delete(*matched)
            _log.info("cache flush: deleted %d analytics keys", len(matched))
        else:
            _log.info("cache flush: would delete %d analytics keys", len(matched))
    finally:
        with contextlib.suppress(Exception):
            await client.aclose()


async def _run(apply: bool) -> int:
    _configure_logging()
    sm = get_sessionmaker()
    mode = "APPLY" if apply else "DRY-RUN"
    _log.info("holding-pen backfill starting mode=%s", mode)

    candidates = await discover_candidates(sm)
    counts = per_user_counts(candidates)
    total = len(candidates)

    _log.info("discover: total=%d affected_users=%d", total, len(counts))
    if counts:
        for uid in sorted(counts):
            _log.info("  user_id=%s would_flag=%d", uid, counts[uid])

    if not apply:
        _log.info("holding-pen backfill done mode=%s total_would_flag=%d", mode, total)
        return 0

    updated = await apply_flags(sm, candidates)
    _log.info("applied: rows_flagged=%d (of %d planned)", updated, total)

    await _flush_analytics_caches(sorted(counts), apply=True)

    _log.info(
        "holding-pen backfill done mode=%s total_flagged=%d affected_users=%d",
        mode,
        updated,
        len(counts),
    )
    return 0


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m parser_service.scripts.backfill_holding_pen",
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
        help="Actually flag the rows as pending_review.",
    )
    args = parser.parse_args(argv)
    apply = bool(args.apply)
    return asyncio.run(_run(apply=apply))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
