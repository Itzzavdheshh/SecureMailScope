"""
Jobs API router.
Provides endpoints for querying analysis job status and triggering job state transitions.
Phase 2 Foundation: Creates/updates job records without running packet parsing.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.db.session import get_db
from app.models import AnalysisJob, Capture, JobStatus
from app.schemas import AnalysisJobRead
from app.analyzers.pipeline import run_phase3_pipeline

router = APIRouter(prefix="/jobs", tags=["jobs"])


class JobStartResponse(BaseModel):
    job: AnalysisJobRead
    message: str = "Phase 3 TCP flow reconstruction and session identification completed successfully."


@router.get(
    "/{job_id}",
    response_model=AnalysisJobRead,
    summary="Get analysis job status",
    description="Retrieve execution status, metrics, and risk summary for an analysis job.",
)
async def get_job(
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
    summary="Start/Queue analysis job",
    description=(
        "Executes Phase 3 TCP flow reconstruction, stream reassembly, and email session identification."
    ),
)
async def start_job(
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

    # Fetch capture
    cap_stmt = select(Capture).where(Capture.id == job.capture_id)
    cap_res = await db.execute(cap_stmt)
    capture = cap_res.scalar_one_or_none()

    if not capture:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture record for job '{job_id}' not found.",
        )

    # Run Phase 3 Pipeline
    await run_phase3_pipeline(capture, job, db)

    return JobStartResponse(
        job=AnalysisJobRead.model_validate(job),
    )

