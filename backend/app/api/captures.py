"""
Captures API router.
Provides endpoints for PCAP/PCAPNG uploading, listing, and inspection.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.db.session import get_db
from app.models import Capture, AnalysisJob
from app.schemas import CaptureRead, AnalysisJobRead
from app.services.capture_service import ingest_pcap_upload

router = APIRouter(prefix="/captures", tags=["captures"])


class CaptureUploadResponse(BaseModel):
    capture: CaptureRead
    job_id: str
    job_status: str
    message: str = "Capture uploaded and validated successfully."


class CaptureListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[CaptureRead]


@router.post(
    "/upload",
    response_model=CaptureUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload PCAP/PCAPNG file",
    description=(
        "Upload a network capture file (.pcap or .pcapng). "
        "Performs extension, magic byte, size limit, and SHA-256 duplicate validation. "
        "Stores file securely and creates an associated AnalysisJob."
    ),
)
async def upload_capture(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
) -> CaptureUploadResponse:
    capture, job = await ingest_pcap_upload(file, db)
    return CaptureUploadResponse(
        capture=CaptureRead.model_validate(capture),
        job_id=job.id,
        job_status=job.status.value,
    )


@router.get(
    "",
    response_model=CaptureListResponse,
    summary="List ingested captures",
    description="Returns a paginated list of all uploaded captures sorted by creation date.",
)
async def list_captures(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> CaptureListResponse:
    # Total count
    count_stmt = select(func.count(Capture.id))
    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one()

    # Paginated items
    stmt = (
        select(Capture)
        .order_by(Capture.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    captures = res.scalars().all()

    return CaptureListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[CaptureRead.model_validate(c) for c in captures],
    )


@router.get(
    "/{capture_id}",
    response_model=CaptureRead,
    summary="Get capture details",
    description="Retrieve details for a specific capture by ID.",
)
async def get_capture(
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


@router.get(
    "/{capture_id}/jobs",
    response_model=List[AnalysisJobRead],
    summary="List jobs for capture",
    description="Retrieve all analysis jobs associated with a specific capture.",
)
async def list_jobs_for_capture(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
) -> List[AnalysisJobRead]:
    stmt = (
        select(AnalysisJob)
        .where(AnalysisJob.capture_id == capture_id)
        .order_by(AnalysisJob.created_at.desc())
    )
    res = await db.execute(stmt)
    jobs = res.scalars().all()

    return [AnalysisJobRead.model_validate(j) for j in jobs]
