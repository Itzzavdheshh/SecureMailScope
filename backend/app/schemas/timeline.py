"""
Timeline Pydantic schemas.
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.enums import Severity


class TimelineEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    session_id: Optional[str] = None
    timestamp: float
    event_type: str
    frame_number: Optional[int] = None
    summary: str
    detail_json: Optional[str] = None
    severity: Severity
