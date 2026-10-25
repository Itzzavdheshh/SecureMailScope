"""
API v1 Captures router.
Provides paginated listing, detail inspection, and secure upload for network capture files.
"""

import math
from typing import List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models import Capture, AnalysisJob
from app.schemas import (
    CaptureRead,
    AnalysisJobRead,
    PaginatedResponse,
)
from app.services.capture_service import ingest_pcap_upload
from app.services.query_service import get_paginated_captures

router = APIRouter()


class CaptureUploadResponse(CaptureRead):
    job_id: str
    job_status: str
    message: str = "Capture uploaded and validated successfully."


@router.post(
    "",
    response_model=CaptureUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload PCAP/PCAPNG file (v1)",
    description="Secure intake and storage of network packet capture files (.pcap or .pcapng).",
)
async def upload_capture_v1(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
) -> CaptureUploadResponse:
    capture, job = await ingest_pcap_upload(file, db)
    return CaptureUploadResponse(
        id=capture.id,
        filename=capture.filename,
        file_path=capture.file_path,
        file_size_bytes=capture.file_size_bytes,
        sha256_hash=capture.sha256_hash,
        total_packets=capture.total_packets,
        capture_start_time=capture.capture_start_time,
        capture_end_time=capture.capture_end_time,
        status=capture.status.value if hasattr(capture.status, "value") else str(capture.status),
        created_at=capture.created_at,
        updated_at=capture.updated_at,
        job_id=job.id,
        job_status=job.status.value if hasattr(job.status, "value") else str(job.status),
    )


@router.get(
    "",
    response_model=PaginatedResponse[CaptureRead],
    summary="List captures (v1)",
    description="Retrieve a paginated list of all ingested capture records with pagination metadata.",
)
async def list_captures_v1(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[CaptureRead]:
    items, total = await get_paginated_captures(db, page=page, page_size=page_size)
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[CaptureRead](
        items=[CaptureRead.model_validate(c) for c in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{capture_id}",
    response_model=CaptureRead,
    summary="Get capture details (v1)",
    description="Retrieve details for a specific capture by UUID.",
)
async def get_capture_v1(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
) -> CaptureRead:
    stmt = select(Capture).where(Capture.id == capture_id)
    res = await db.execute(stmt)
    capture = res.scalar_one_or_none()

    if not capture:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture with ID '{capture_id}' not found.",
        )

    return CaptureRead.model_validate(capture)
