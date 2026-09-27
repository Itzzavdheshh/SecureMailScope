"""
Pydantic Schemas for Security Rule Engine & Risk Scoring.
Defines data structures for YAML rule parsing, validation, and risk weights configuration.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models.enums import Confidence, FindingCategory, Severity


class DetectionCondition(BaseModel):
    field: str
    condition: str
    value: Any


class AdditionalCondition(BaseModel):
    field: str
    condition: str
    value: Any


class EvidenceRequirements(BaseModel):
    requires: List[str] = Field(default_factory=list)


class RuleDefinition(BaseModel):
    id: str
    title: str
    severity: Severity
    description: str
    rationale: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    enabled: bool = True
    category: Optional[FindingCategory] = None
    detection: DetectionCondition
    additional_condition: Optional[AdditionalCondition] = None
    evidence_requirements: Optional[EvidenceRequirements] = None
    confidence_when_missing: Optional[str] = "INSUFFICIENT_EVIDENCE"
    confidence_note: Optional[str] = None
    risk_weight: Optional[float] = None


class RuleSet(BaseModel):
    version: str = "1.0.0"
    schema_url: Optional[str] = Field(default=None, alias="schema")
    rules: List[RuleDefinition] = Field(default_factory=list)


class RiskWeightsConfig(BaseModel):
    severity_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "CRITICAL": 10.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 1.5,
            "INFO": 0.5,
        }
    )
    confidence_factors: Dict[str, float] = Field(
        default_factory=lambda: {
            "OBSERVED": 1.0,
            "ANALYZED": 0.9,
            "INFERRED": 0.7,
            "INSUFFICIENT_EVIDENCE": 0.0,
        }
    )
    reference_max: float = 30.0
    drift_bonus: float = 2.0
