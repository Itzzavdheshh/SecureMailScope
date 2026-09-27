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
from app.models import AnalysisJob, JobStatus
from app.schemas import AnalysisJobRead

router = APIRouter(prefix="/jobs", tags=["jobs"])


class JobStartResponse(BaseModel):
    job: AnalysisJobRead
    message: str = "Analysis job status set to RUNNING. Analysis pipeline will run in Phase 3."


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
        "Phase 2 Stub: Transitions job status to RUNNING. "
        "Actual packet flow reconstruction and rule analysis will be executed in Phase 3."
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

    if job.status == JobStatus.PENDING:
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(job)

    return JobStartResponse(
        job=AnalysisJobRead.model_validate(job),
    )
