"""
API v1 Findings router.
Provides paginated listing and detail inspection of rule evaluation findings.
"""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas import FindingRead, PaginatedResponse
from app.services.query_service import get_paginated_findings, get_finding_by_id

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[FindingRead],
    summary="List security findings (v1)",
    description="Retrieve a paginated list of security rule findings with severity, category, and rule ID filters.",
)
async def list_findings_v1(
    job_id: Optional[str] = Query(default=None, description="Filter by AnalysisJob ID"),
    session_id: Optional[str] = Query(default=None, description="Filter by Session ID"),
    capture_id: Optional[str] = Query(default=None, description="Filter by Capture ID"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    category: Optional[str] = Query(default=None, description="Filter by category (TLS_CRYPTO, X509_CERT, STARTTLS, PROTOCOL_ANOMALY)"),
    confidence: Optional[str] = Query(default=None, description="Filter by confidence (HIGH, MEDIUM, LOW)"),
    rule_id: Optional[str] = Query(default=None, description="Filter by Rule ID (e.g. CRYPT-001)"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[FindingRead]:
    items, total = await get_paginated_findings(
        db,
        page=page,
        page_size=page_size,
        job_id=job_id,
        session_id=session_id,
        capture_id=capture_id,
        severity=severity,
        category=category,
        confidence=confidence,
        rule_id=rule_id,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[FindingRead](
        items=[FindingRead.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingRead,
    summary="Get finding details (v1)",
    description="Retrieve details and attached packet evidence for a specific finding by UUID.",
)
async def get_finding_v1(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> FindingRead:
    finding = await get_finding_by_id(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found.",
        )
    return FindingRead.model_validate(finding)
