"""
AnalysisJob Pydantic schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.enums import JobStatus, RiskBand


class AnalysisJobCreate(BaseModel):
    capture_id: str
    options_json: Optional[str] = None


class AnalysisJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    status: JobStatus
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    options_json: Optional[str] = None
    total_sessions: int
    total_findings: int
    overall_risk_score: Optional[float] = None
    risk_band: Optional[RiskBand] = None
    created_at: datetime
