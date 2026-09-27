"""
API v1 Drift Events router.
Provides paginated listing and detail inspection of cryptographic drift events.
"""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas import DriftEventRead, PaginatedResponse
from app.services.query_service import get_paginated_drifts, get_drift_by_id

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[DriftEventRead],
    summary="List drift events (v1)",
    description="Retrieve a paginated list of cryptographic drift events with optional filters.",
)
async def list_drifts_v1(
    infrastructure_id: Optional[str] = Query(default=None, description="Filter by Infrastructure Identity ID"),
    job_id: Optional[str] = Query(default=None, description="Filter by AnalysisJob ID"),
    capture_id: Optional[str] = Query(default=None, description="Filter by Capture ID"),
    event_type: Optional[str] = Query(default=None, description="Filter by drift type (e.g. TLS_VERSION_DOWNGRADE, CERT_CHANGED, STARTTLS_DISABLED)"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[DriftEventRead]:
    items, total = await get_paginated_drifts(
        db,
        page=page,
        page_size=page_size,
        infrastructure_id=infrastructure_id,
        job_id=job_id,
        capture_id=capture_id,
        event_type=event_type,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[DriftEventRead](
        items=[DriftEventRead.model_validate(d) for d in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{drift_id}",
    response_model=DriftEventRead,
    summary="Get drift event detail (v1)",
    description="Retrieve detailed cryptographic baseline drift information by UUID.",
)
async def get_drift_v1(
    drift_id: str,
    db: AsyncSession = Depends(get_db),
) -> DriftEventRead:
    drift = await get_drift_by_id(db, drift_id)
    if not drift:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Drift event with ID '{drift_id}' not found.",
        )
    return DriftEventRead.model_validate(drift)
