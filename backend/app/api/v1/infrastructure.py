"""
API v1 Infrastructure router.
Provides paginated listing and detail inspection of stable infrastructure identities.
"""

import math
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas import InfrastructureIdentityRead, PaginatedResponse
from app.services.query_service import get_paginated_infrastructure, get_infrastructure_by_id

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[InfrastructureIdentityRead],
    summary="List infrastructure identities (v1)",
    description="Retrieve a paginated list of stable infrastructure identities tracked across email analysis runs.",
)
async def list_infrastructure_v1(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[InfrastructureIdentityRead]:
    items, total = await get_paginated_infrastructure(db, page=page, page_size=page_size)
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[InfrastructureIdentityRead](
        items=[InfrastructureIdentityRead.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{identity_id}",
    response_model=InfrastructureIdentityRead,
    summary="Get infrastructure identity details (v1)",
    description="Retrieve stable infrastructure identity, cryptographic profile, and associated drift events.",
)
async def get_infrastructure_v1(
    identity_id: str,
    db: AsyncSession = Depends(get_db),
) -> InfrastructureIdentityRead:
    identity = await get_infrastructure_by_id(db, identity_id)
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Infrastructure identity with ID '{identity_id}' not found.",
        )
    return InfrastructureIdentityRead.model_validate(identity)
