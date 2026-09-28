"""
Domain models export module.
Importing this package registers all SQLAlchemy models with Base.metadata.
"""

from app.db.session import Base
from app.models.enums import (
    JobStatus,
    ProtocolType,
    StarttlsStatus,
    Severity,
    Confidence,
    EvidenceStatus,
    FindingCategory,
    RiskBand,
    DriftEventType,
)
from app.models.capture import Capture
from app.models.job import AnalysisJob
from app.models.session import EmailSession, StarttlsState, TlsHandshake
from app.models.certificate import Certificate, CertificateChain
from app.models.finding import Finding, Evidence
from app.models.infrastructure import InfrastructureIdentity, DriftEvent
from app.models.timeline import TimelineEvent
from app.models.behavioral import BehavioralAnalysis

__all__ = [
    "Base",
    "JobStatus",
    "ProtocolType",
    "StarttlsStatus",
    "Severity",
    "Confidence",
    "EvidenceStatus",
    "FindingCategory",
    "RiskBand",
    "DriftEventType",
    "Capture",
    "AnalysisJob",
    "EmailSession",
    "StarttlsState",
    "TlsHandshake",
    "Certificate",
    "CertificateChain",
    "Finding",
    "Evidence",
    "InfrastructureIdentity",
    "DriftEvent",
    "TimelineEvent",
    "BehavioralAnalysis",
]
