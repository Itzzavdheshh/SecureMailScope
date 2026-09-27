"""
API v1 Forensic Timeline router.
Provides timeline sequence retrieval for analysis jobs.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas import TimelineEventRead
from app.services.query_service import get_timeline_events

router = APIRouter()


@router.get(
    "/jobs/{job_id}/timeline",
    response_model=List[TimelineEventRead],
    summary="Get job timeline (v1)",
    description="Retrieve chronological forensic timeline events for an analysis job, ordered by timestamp and frame number.",
)
async def get_job_timeline_v1(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> List[TimelineEventRead]:
    events = await get_timeline_events(db, job_id=job_id)
    return [TimelineEventRead.model_validate(e) for e in events]
