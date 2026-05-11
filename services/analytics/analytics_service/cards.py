"""Card search router.

Reads ``catalog.cards`` (the Scryfall bulk-data mirror) for card-name
lookups. The mirror is refreshed by the background sync; this router
is the read side that surfaces the data to logged-in users.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_user

router = APIRouter(prefix="/analytics/cards", tags=["cards"])

_RESULT_LIMIT = 20


class CardResult(BaseModel):
    name: str
    mana_cost: str | None = None
    type_line: str | None = None
    oracle_text: str | None = None
    image_uri: str | None = None
    set_code: str | None = None


@router.get("", response_model=list[CardResult])
async def search_cards(
    q: str = "",
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> list[CardResult]:
    """Case-insensitive substring search on card name.

    Blank queries return an empty list — there is no value in dumping
    the first 20 cards by storage order.
    """
    needle = q.strip()
    if not needle:
        return []
    rows = (
        await db.execute(
            text(
                """
                SELECT name, mana_cost, type_line, oracle_text, image_uri, set_code
                FROM catalog.cards
                WHERE name ILIKE :pattern
                ORDER BY name
                LIMIT :limit
                """
            ),
            {"pattern": f"%{needle}%", "limit": _RESULT_LIMIT},
        )
    ).all()
    return [
        CardResult(
            name=str(name),
            mana_cost=mana_cost,
            type_line=type_line,
            oracle_text=oracle_text,
            image_uri=image_uri,
            set_code=set_code,
        )
        for (name, mana_cost, type_line, oracle_text, image_uri, set_code) in rows
    ]
