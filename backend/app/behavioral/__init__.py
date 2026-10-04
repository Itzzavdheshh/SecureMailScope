"""
SecureMailScope — Phase 10 Behavioral Analysis Package.

Implements explainable behavioral deviation analysis of cryptographic communication
patterns relative to established infrastructure baselines.

Core principle:
  DETERMINISTIC FORENSICS establishes WHAT WAS OBSERVED.
  BEHAVIORAL ANALYSIS identifies WHAT DEVIATED FROM BASELINE.
  It NEVER claims WHO caused a change or attacker intent.
"""

from app.behavioral.engine import (
    BehavioralAnalysisEngine,
    BehavioralAnalysisResult,
    BehavioralAnomaly,
    AnalysisMethodStatus,
    ISOLATION_FOREST_MIN_OBSERVATIONS,
)

__all__ = [
    "BehavioralAnalysisEngine",
    "BehavioralAnalysisResult",
    "BehavioralAnomaly",
    "AnalysisMethodStatus",
    "ISOLATION_FOREST_MIN_OBSERVATIONS",
]
