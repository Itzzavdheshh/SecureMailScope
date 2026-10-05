"""
API v1 Jobs router.
Provides paginated listing, status inspection, and pipeline triggers for AnalysisJob records.
"""

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.db.session import get_db
from app.models import AnalysisJob, Capture, JobStatus
from app.schemas import AnalysisJobRead, PaginatedResponse
from app.services.query_service import get_paginated_jobs
from app.analyzers.pipeline import run_pipeline

router = APIRouter()


class JobStartResponse(BaseModel):
    job: AnalysisJobRead
    message: str = "Analysis pipeline completed successfully."


@router.get(
    "",
    response_model=PaginatedResponse[AnalysisJobRead],
    summary="List jobs (v1)",
    description="Retrieve a paginated list of all analysis jobs.",
)
async def list_jobs_v1(
    capture_id: Optional[str] = Query(default=None, description="Filter jobs by capture ID"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[AnalysisJobRead]:
    items, total = await get_paginated_jobs(db, page=page, page_size=page_size, capture_id=capture_id)
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[AnalysisJobRead](
        items=[AnalysisJobRead.model_validate(j) for j in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{job_id}",
    response_model=AnalysisJobRead,
    summary="Get job status (v1)",
    description="Retrieve status, risk score, and session metrics for an analysis job.",
)
async def get_job_v1(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> AnalysisJobRead:
    stmt = select(AnalysisJob).where(AnalysisJob.id == job_id)
    res = await db.execute(stmt)
    job = res.scalar_one_or_none()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found.",
        )

    return AnalysisJobRead.model_validate(job)


@router.post(
    "/{job_id}/start",
    response_model=JobStartResponse,
    summary="Start analysis job pipeline (v1)",
    description="Executes full PCAP analysis pipeline for an analysis job.",
)
async def start_job_v1(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> JobStartResponse:
    stmt = select(AnalysisJob).where(AnalysisJob.id == job_id)
    res = await db.execute(stmt)
    job = res.scalar_one_or_none()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found.",
        )

    if job.status != JobStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Analysis job '{job_id}' is {job.status.value}; only PENDING jobs can start. "
                "Create a new analysis job to reprocess this capture."
            ),
        )

    cap_stmt = select(Capture).where(Capture.id == job.capture_id)
    cap_res = await db.execute(cap_stmt)
    capture = cap_res.scalar_one_or_none()

    if not capture:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture record for job '{job_id}' not found.",
        )

    await run_pipeline(capture, job, db)

    return JobStartResponse(
        job=AnalysisJobRead.model_validate(job),
    )
