"""
Infrastructure & Drift Pydantic schemas.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.models.enums import DriftEventType, RiskBand


class DriftEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    infrastructure_id: str
    capture_id: Optional[str] = None
    job_id: Optional[str] = None
    event_type: DriftEventType
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    delta_description: str
    risk_delta: float
    detected_at: datetime


class InfrastructureIdentityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ip_address: str
    hostname: Optional[str] = None
    organization: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    current_risk_score: Optional[float] = None
    current_risk_band: Optional[RiskBand] = None
    last_evaluated_job_id: Optional[str] = None
    drift_events: List[DriftEventRead] = []
