"""Archetype catalog router.

Read endpoints (list, classify) and admin CRUD on the
``analytics.archetypes`` catalog table. The classifier is a thin route
over :func:`analytics_service.classifier.classify` — the algorithm
itself is unit-tested in isolation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from analytics_service.classifier import classify
from analytics_service.db import get_session
from analytics_service.deps import AuthenticatedUser, require_admin, require_user
from analytics_service.models import Archetype
from analytics_service.schemas import (
    ArchetypeListView,
    ArchetypeRecord,
    ArchetypeWriteRequest,
    ClassifyRequest,
    ClassifyResult,
)

router = APIRouter(prefix="/analytics/archetypes", tags=["archetypes"])


def _record(row: Archetype) -> ArchetypeRecord:
    return ArchetypeRecord(
        id=row.id,
        name=row.name,
        format=row.format,
        defining_cards=list(row.defining_cards or []),
        sample_decklists=row.sample_decklists,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("", response_model=ArchetypeListView)
async def list_archetypes(
    _user: AuthenticatedUser = Depends(require_user),
    db: AsyncSession = Depends(get_session),
) -> ArchetypeListView:
    rows = (
        (await db.execute(select(Archetype).order_by(Archetype.format, Archetype.name)))
        .scalars()
        .all()
    )
    total = int((await db.execute(select(func.count()).select_from(Archetype))).scalar_one())
    return ArchetypeListView(archetypes=[_record(r) for r in rows], total=total)


@router.post("/classify", response_model=ClassifyResult)
async def classify_endpoint(
    body: ClassifyRequest,
    db: AsyncSession = Depends(get_session),
) -> ClassifyResult:
    """Classify a decklist against the catalog.

    No auth — the endpoint is a stateless utility intended for the
    parser worker (which holds no JWT) and any internal caller. It
    leaks no information beyond what GET /archetypes already exposes.
    """
    if not body.card_names:
        return ClassifyResult()
    rows = (await db.execute(select(Archetype))).scalars().all()
    if not rows:
        return ClassifyResult()
    outcome = classify(body.card_names, rows)
    if outcome.archetype is None:
        return ClassifyResult()
    arch = outcome.archetype
    # The archetype here is one of the SQLAlchemy rows we just loaded,
    # so the attribute access is safe; type narrowing via the protocol
    # in classifier.py keeps it duck-typed for unit tests.
    assert isinstance(arch, Archetype)
    return ClassifyResult(
        archetype_id=arch.id,
        archetype_name=arch.name,
        format=arch.format,
        confidence=outcome.confidence,
    )


@router.post(
    "",
    response_model=ArchetypeRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_archetype(
    body: ArchetypeWriteRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> ArchetypeRecord:
    row = Archetype(
        id=uuid.uuid4(),
        name=body.name,
        format=body.format,
        defining_cards=list(body.defining_cards),
        sample_decklists=body.sample_decklists,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _record(row)


@router.get("/{archetype_id}", response_model=ArchetypeRecord)
async def get_archetype(
    archetype_id: uuid.UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> ArchetypeRecord:
    row = (
        await db.execute(select(Archetype).where(Archetype.id == archetype_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "archetype_not_found"},
        )
    return _record(row)


@router.put("/{archetype_id}", response_model=ArchetypeRecord)
async def update_archetype(
    archetype_id: uuid.UUID,
    body: ArchetypeWriteRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> ArchetypeRecord:
    row = (
        await db.execute(select(Archetype).where(Archetype.id == archetype_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "archetype_not_found"},
        )
    row.name = body.name
    row.format = body.format
    row.defining_cards = list(body.defining_cards)
    row.sample_decklists = body.sample_decklists
    row.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(row)
    return _record(row)


@router.delete("/{archetype_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_archetype(
    archetype_id: uuid.UUID,
    _admin: AuthenticatedUser = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
) -> Response:
    result = await db.execute(delete(Archetype).where(Archetype.id == archetype_id))
    await db.commit()
    # SQLAlchemy's async ``execute`` returns ``Result``; for DML the
    # underlying object is a ``CursorResult`` carrying ``rowcount``.
    # Cast through ``Any`` to keep mypy quiet without disabling checks.
    rowcount: int = result.rowcount  # type: ignore[attr-defined]
    if rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "archetype_not_found"},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
