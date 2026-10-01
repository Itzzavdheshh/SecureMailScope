"""
Risk & Security Posture Pydantic schemas.
"""

from typing import Dict, Optional
from pydantic import BaseModel
from app.models.enums import RiskBand


class RiskSummaryResponse(BaseModel):
    """
    Structured security posture and risk calculation summary.
    """
    capture_id: Optional[str] = None
    job_id: Optional[str] = None
    overall_risk_score: float
    risk_band: RiskBand
    total_sessions: int
    total_findings: int
    severity_distribution: Dict[str, int]
    drift_count: int
    high_risk_session_count: int
