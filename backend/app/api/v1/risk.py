"""
API v1 Risk and Posture router.
Exposes actual posture score metrics and risk distributions using Phase 5 risk calculator.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.risk import RiskSummaryResponse
from app.services.query_service import get_risk_summary

router = APIRouter()


@router.get(
    "/captures/{capture_id}/risk",
    response_model=RiskSummaryResponse,
    summary="Get capture risk summary (v1)",
    description="Retrieve security posture metrics, overall risk score, risk band, severity distribution, and high-risk session metrics for a capture.",
)
async def get_capture_risk_v1(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
) -> RiskSummaryResponse:
    risk_summary = await get_risk_summary(db, capture_id=capture_id)
    if not risk_summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture with ID '{capture_id}' not found or has no analysis results.",
        )
    return risk_summary


@router.get(
    "/jobs/{job_id}/risk",
    response_model=RiskSummaryResponse,
    summary="Get job risk summary (v1)",
    description="Retrieve security posture metrics for a specific analysis job.",
)
async def get_job_risk_v1(
    job_id: str,
    db: AsyncSession = Depends(get_db),
) -> RiskSummaryResponse:
    risk_summary = await get_risk_summary(db, job_id=job_id)
    if not risk_summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisJob with ID '{job_id}' not found.",
        )
    return risk_summary
