"""
API v1 Sessions router.
Provides paginated listing, detail inspection, and session timeline events.
"""

import math
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas import EmailSessionRead, TimelineEventRead, PaginatedResponse
from app.services.query_service import (
    get_paginated_sessions,
    get_session_by_id,
    get_timeline_events,
)

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedResponse[EmailSessionRead],
    summary="List email sessions (v1)",
    description="Retrieve a paginated list of reconstructed mail sessions with optional protocol, host, and risk filters.",
)
async def list_sessions_v1(
    capture_id: Optional[str] = Query(default=None, description="Filter by Capture ID"),
    job_id: Optional[str] = Query(default=None, description="Filter by AnalysisJob ID"),
    protocol: Optional[str] = Query(default=None, description="Filter by protocol (SMTP, IMAP, POP3)"),
    server_ip: Optional[str] = Query(default=None, description="Filter by server IP"),
    server_port: Optional[int] = Query(default=None, description="Filter by server port"),
    hostname: Optional[str] = Query(default=None, description="Filter by server hostname"),
    tls_version: Optional[str] = Query(default=None, description="Filter by negotiated TLS version"),
    cipher: Optional[str] = Query(default=None, description="Filter by negotiated cipher suite"),
    starttls_state: Optional[str] = Query(default=None, description="Filter by STARTTLS status"),
    min_risk: Optional[float] = Query(default=None, description="Minimum session risk score"),
    max_risk: Optional[float] = Query(default=None, description="Maximum session risk score"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[EmailSessionRead]:
    items, total = await get_paginated_sessions(
        db,
        page=page,
        page_size=page_size,
        capture_id=capture_id,
        job_id=job_id,
        protocol=protocol,
        server_ip=server_ip,
        server_port=server_port,
        hostname=hostname,
        tls_version=tls_version,
        cipher=cipher,
        starttls_state=starttls_state,
        min_risk=min_risk,
        max_risk=max_risk,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[EmailSessionRead](
        items=[EmailSessionRead.model_validate(s) for s in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{session_id}",
    response_model=EmailSessionRead,
    summary="Get session details (v1)",
    description="Retrieve details for a specific email session by UUID.",
)
async def get_session_v1(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> EmailSessionRead:
    session = await get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"EmailSession with ID '{session_id}' not found.",
        )
    return EmailSessionRead.model_validate(session)


@router.get(
    "/{session_id}/timeline",
    response_model=List[TimelineEventRead],
    summary="Get session timeline (v1)",
    description="Retrieve chronological forensic network timeline events for a specific email session.",
)
async def get_session_timeline_v1(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> List[TimelineEventRead]:
    session = await get_session_by_id(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"EmailSession with ID '{session_id}' not found.",
        )
    events = await get_timeline_events(db, session_id=session_id)
    return [TimelineEventRead.model_validate(e) for e in events]
