"""
Transparent Risk Scoring Engine.
Computes session risk score (0.0 - 100.0) and aggregate job risk score (0.0 - 100.0)
using the transparent formula documented in rules/risk_weights.yaml.
"""

from typing import List, Optional, Tuple
import structlog

from app.models.enums import Confidence, RiskBand, Severity
from app.models.finding import Finding
from app.rules.schema import RiskWeightsConfig

log = structlog.get_logger(__name__)


def compute_finding_contribution(
    severity: Severity,
    confidence: Confidence,
    config: RiskWeightsConfig
) -> float:
    """
    Calculate raw risk contribution for a single finding:
    contribution = severity_weight * confidence_factor
    """
    sev_key = severity.value if isinstance(severity, Severity) else str(severity)
    conf_key = confidence.value if isinstance(confidence, Confidence) else str(confidence)

    w = config.severity_weights.get(sev_key, 5.0)
    c = config.confidence_factors.get(conf_key, 1.0)
    return round(w * c, 2)


def calculate_session_risk_score(
    findings: List[Finding],
    config: Optional[RiskWeightsConfig] = None,
    is_drift_event: bool = False
) -> Tuple[float, RiskBand]:
    """
    Calculate deterministic session risk score (0.0 - 100.0).

    Formula:
      raw_score = sum(severity_weight * confidence_factor) + (drift_bonus if is_drift_event)
      normalized_score = min(100.0, round(raw_score / reference_max * 100, 1))
    """
    cfg = config or RiskWeightsConfig()

    if not findings and not is_drift_event:
        return 0.0, RiskBand.SECURE

    raw_score = 0.0
    for f in findings:
        contribution = compute_finding_contribution(f.severity, f.confidence, cfg)
        f.score_contribution = contribution
        raw_score += contribution

    if is_drift_event:
        raw_score += cfg.drift_bonus

    normalized = min(100.0, round((raw_score / cfg.reference_max) * 100.0, 1))

    # Map to RiskBand enum
    if normalized >= 80.0:
        band = RiskBand.CRITICAL
    elif normalized >= 60.0:
        band = RiskBand.HIGH
    elif normalized >= 40.0:
        band = RiskBand.MEDIUM
    elif normalized >= 20.0:
        band = RiskBand.LOW
    else:
        band = RiskBand.SECURE

    return normalized, band


def calculate_job_risk_score(session_scores: List[float]) -> float:
    """
    Calculate deterministic aggregate job risk score (0.0 - 100.0) from session scores.

    Formula:
      job_score = min(100.0, round(0.7 * max(session_scores) + 0.3 * avg(session_scores), 1))
    """
    if not session_scores:
        return 0.0

    max_score = max(session_scores)
    avg_score = sum(session_scores) / len(session_scores)

    job_score = min(100.0, round(0.7 * max_score + 0.3 * avg_score, 1))
    return job_score


def calculate_job_risk_band(score: float) -> RiskBand:
    if score >= 80.0:
        return RiskBand.CRITICAL
    elif score >= 60.0:
        return RiskBand.HIGH
    elif score >= 40.0:
        return RiskBand.MEDIUM
    elif score >= 20.0:
        return RiskBand.LOW
    else:
        return RiskBand.SECURE
