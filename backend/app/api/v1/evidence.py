"""
API v1 Evidence router.
Provides paginated listing and detail inspection of forensic packet evidence.
"""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas import EvidenceRead, PaginatedResponse
from app.services.query_service import get_paginated_evidence, get_evidence_by_id

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[EvidenceRead],
    summary="List forensic evidence (v1)",
    description="Retrieve a paginated list of forensic evidence items with session, capture, frame, layer, and field filters.",
)
async def list_evidence_v1(
    finding_id: Optional[str] = Query(default=None, description="Filter by Finding ID"),
    session_id: Optional[str] = Query(default=None, description="Filter by Session ID"),
    capture_id: Optional[str] = Query(default=None, description="Filter by Capture ID"),
    frame_number: Optional[int] = Query(default=None, description="Filter by frame number"),
    protocol_layer: Optional[str] = Query(default=None, description="Filter by protocol layer (e.g. TCP, TLS, SMTP)"),
    field_name: Optional[str] = Query(default=None, description="Filter by field name"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[EvidenceRead]:
    items, total = await get_paginated_evidence(
        db,
        page=page,
        page_size=page_size,
        finding_id=finding_id,
        session_id=session_id,
        capture_id=capture_id,
        frame_number=frame_number,
        protocol_layer=protocol_layer,
        field_name=field_name,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[EvidenceRead](
        items=[EvidenceRead.model_validate(e) for e in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{evidence_id}",
    response_model=EvidenceRead,
    summary="Get evidence detail (v1)",
    description="Retrieve detailed forensic lineage for a specific evidence item by UUID.",
)
async def get_evidence_v1(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
) -> EvidenceRead:
    evidence = await get_evidence_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found.",
        )
    return EvidenceRead.model_validate(evidence)
