"""
AnalysisJob Pydantic schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, model_validator
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
    total_sessions: int = 0
    total_findings: int = 0
    overall_risk_score: Optional[float] = None
    risk_band: Optional[RiskBand] = None
    created_at: datetime

    @model_validator(mode="after")
    def _fill_job_defaults(self):
        if self.risk_band is None and self.overall_risk_score is not None:
            from app.rules.risk_calculator import calculate_job_risk_band
            self.risk_band = calculate_job_risk_band(self.overall_risk_score)
        return self
