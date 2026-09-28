"""
API v1 Behavioral Analysis router — Phase 10.

Provides REST endpoints to query persisted behavioural deviation analysis results.
All endpoints return only previously-stored results (analysis runs during pipeline).
No on-demand analysis is triggered here — the pipeline handles that.
"""

import json
import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.behavioral import BehavioralAnalysis

router = APIRouter()


# ── Response Schemas ──────────────────────────────────────────────────────────

class BehavioralAnalysisRead(BaseModel):
    """Pydantic read schema for a persisted BehavioralAnalysis result."""
    id: str
    infrastructure_id: str
    job_id: str
    session_id: Optional[str]
    identity_key: str
    baseline_status: str
    observation_count: int
    overall_status: str
    significant_deviation_detected: bool
    deviation_summary: str
    anomaly_count: int
    anomalies: list
    risk_stat_analysis: Optional[dict]
    isolation_forest: Optional[dict]
    limitations: list
    analyzed_at: str

    model_config = {"from_attributes": True}


class PaginatedBehavioralResponse(BaseModel):
    items: list[BehavioralAnalysisRead]
    total: int
    page: int
    page_size: int
    total_pages: int


def _deserialize(record: BehavioralAnalysis) -> BehavioralAnalysisRead:
    """Map ORM row → Pydantic schema, safely deserialising JSON blobs."""
    def safe_loads(val: Optional[str], default):
        if val is None:
            return default
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return default

    return BehavioralAnalysisRead(
        id=record.id,
        infrastructure_id=record.infrastructure_id,
        job_id=record.job_id,
        session_id=record.session_id,
        identity_key=record.identity_key,
        baseline_status=record.baseline_status,
        observation_count=record.observation_count,
        overall_status=record.overall_status.value if hasattr(record.overall_status, "value") else str(record.overall_status),
        significant_deviation_detected=record.significant_deviation_detected,
        deviation_summary=record.deviation_summary,
        anomaly_count=record.anomaly_count,
        anomalies=safe_loads(record.anomalies_json, []),
        risk_stat_analysis=safe_loads(record.risk_stat_json, None),
        isolation_forest=safe_loads(record.isolation_forest_json, None),
        limitations=safe_loads(record.limitations_json, []),
        analyzed_at=record.analyzed_at.isoformat() if record.analyzed_at else "",
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=PaginatedBehavioralResponse,
    summary="List behavioural analysis results (v1)",
    description=(
        "Retrieve paginated behavioural deviation analysis results. "
        "Optionally filter by job_id, infrastructure_id, or deviation flag."
    ),
)
async def list_behavioral_analyses(
    job_id: Optional[str] = Query(default=None, description="Filter by analysis job ID"),
    infrastructure_id: Optional[str] = Query(default=None, description="Filter by infrastructure identity ID"),
    significant_only: bool = Query(default=False, description="Return only results with significant_deviation_detected=True"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedBehavioralResponse:
    query = select(BehavioralAnalysis)

    if job_id:
        query = query.where(BehavioralAnalysis.job_id == job_id)
    if infrastructure_id:
        query = query.where(BehavioralAnalysis.infrastructure_id == infrastructure_id)
    if significant_only:
        query = query.where(BehavioralAnalysis.significant_deviation_detected.is_(True))

    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        query
        .order_by(BehavioralAnalysis.analyzed_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    res = await db.execute(stmt)
    records = list(res.scalars().all())

    total_pages = math.ceil(total / page_size) if total > 0 else 0
    return PaginatedBehavioralResponse(
        items=[_deserialize(r) for r in records],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{analysis_id}",
    response_model=BehavioralAnalysisRead,
    summary="Get behavioural analysis result (v1)",
    description="Retrieve a single behavioural deviation analysis result by its ID.",
)
async def get_behavioral_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
) -> BehavioralAnalysisRead:
    stmt = select(BehavioralAnalysis).where(BehavioralAnalysis.id == analysis_id)
    res = await db.execute(stmt)
    record = res.scalar_one_or_none()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Behavioural analysis result with ID '{analysis_id}' not found.",
        )
    return _deserialize(record)


@router.get(
    "/jobs/{job_id}/summary",
    response_model=dict,
    summary="Behavioural analysis summary for a job (v1)",
    description=(
        "Returns an aggregate summary of all behavioural analyses performed "
        "during a specific analysis job run."
    ),
)
async def get_job_behavioral_summary(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    stmt = select(BehavioralAnalysis).where(BehavioralAnalysis.job_id == job_id)
    res = await db.execute(stmt)
    records = list(res.scalars().all())

    if not records:
        return {
            "job_id": job_id,
            "total_analyses": 0,
            "significant_deviations": 0,
            "insufficient_data": 0,
            "total_anomalies": 0,
            "analyses": [],
        }

    significant = sum(1 for r in records if r.significant_deviation_detected)
    insufficient = sum(
        1 for r in records
        if (r.overall_status.value if hasattr(r.overall_status, "value") else str(r.overall_status))
        == "INSUFFICIENT_EVIDENCE"
    )
    total_anomalies = sum(r.anomaly_count for r in records)

    return {
        "job_id": job_id,
        "total_analyses": len(records),
        "significant_deviations": significant,
        "insufficient_data": insufficient,
        "total_anomalies": total_anomalies,
        "analyses": [_deserialize(r).model_dump() for r in records],
    }
