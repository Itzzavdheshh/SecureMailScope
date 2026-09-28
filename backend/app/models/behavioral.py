"""
SecureMailScope — Phase 10 Behavioral Analysis Persistence Model.

Stores the result of one behavioural deviation analysis run, keyed by
infrastructure identity and analysis job. References existing models for
lineage — does NOT duplicate cryptographic facts.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.enums import EvidenceStatus


class BehavioralAnalysis(Base):
    """
    Behavioural deviation analysis result for one infrastructure identity
    observation, linked to the analysis job that produced it.

    Stores:
    - baseline status + observation count at analysis time
    - overall deviation flag and summary
    - JSON blob for full anomaly list (reference, not duplicated crypto facts)
    - JSON blobs for statistical analysis and Isolation Forest results
    - Evidence status (ANALYZED / INSUFFICIENT_EVIDENCE)
    """
    __tablename__ = "behavioral_analyses"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    infrastructure_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("infrastructure_identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("email_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Baseline context at time of analysis
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    baseline_status: Mapped[str] = mapped_column(String(32), nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Overall analysis result
    overall_status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus), nullable=False, default=EvidenceStatus.ANALYZED
    )
    significant_deviation_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    deviation_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # JSON blobs for detailed results (stored as TEXT / JSON string)
    anomalies_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_stat_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    isolation_forest_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    limitations_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Anomaly count for quick querying
    anomaly_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
