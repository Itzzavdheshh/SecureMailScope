"""
Finding & Evidence Pydantic schemas.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.models.enums import Confidence, EvidenceStatus, FindingCategory, Severity


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    capture_id: str
    session_id: Optional[str] = None
    frame_number: int
    packet_timestamp: float
    protocol_layer: str
    field_name: str
    observed_value: str
    source_reference: Optional[str] = None
    evidence_status: EvidenceStatus
    hex_dump_snippet: Optional[str] = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    session_id: Optional[str] = None
    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    status: EvidenceStatus
    score_contribution: float
    description: str
    remediation_recommendation: Optional[str] = None
    created_at: datetime
    evidence: List[EvidenceRead] = []
