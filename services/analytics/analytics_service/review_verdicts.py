"""Atomic persistence for admin match review decisions."""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_match_review_verdict(
    session: AsyncSession,
    match_id: uuid.UUID,
    review_status: str | None,
) -> int | None:
    """Update a match and its durable verdict record in one transaction.

    Returns the owning user ID, or ``None`` when the match no longer
    exists. The row lock makes the verdict record and match visibility
    change a single boundary when force-reparse is concurrent.
    """
    target = (
        await session.execute(
            text(
                """
                SELECT user_id, raw_match_id, sha256, review_reason
                  FROM parser.matches
                 WHERE id = :match_id
                 FOR UPDATE
                """
            ),
            {"match_id": match_id},
        )
    ).one_or_none()
    if target is None:
        return None

    user_id, raw_match_id, sha256, review_reason = target
    identity_kind = "raw_match_id" if raw_match_id is not None else "source_sha256"
    identity_value = str(raw_match_id) if raw_match_id is not None else str(sha256)
    verdict = review_status if review_status is not None else "accepted"

    await session.execute(
        text(
            """
            INSERT INTO parser.match_review_verdicts
                (user_id, identity_kind, identity_value, source_sha256,
                 verdict, review_reason)
            VALUES
                (:user_id, :identity_kind, :identity_value, :source_sha256,
                 :verdict, :review_reason)
            ON CONFLICT (user_id, identity_kind, identity_value) DO UPDATE
                SET source_sha256 = EXCLUDED.source_sha256,
                    verdict = EXCLUDED.verdict,
                    review_reason = EXCLUDED.review_reason,
                    updated_at = now()
            """
        ),
        {
            "user_id": int(user_id),
            "identity_kind": identity_kind,
            "identity_value": identity_value,
            "source_sha256": str(sha256),
            "verdict": verdict,
            "review_reason": review_reason,
        },
    )
    await session.execute(
        text("UPDATE parser.matches SET review_status = :status WHERE id = :match_id"),
        {"status": review_status, "match_id": match_id},
    )
    return int(user_id)
