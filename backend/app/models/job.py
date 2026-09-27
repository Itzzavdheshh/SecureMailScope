"""
AnalysisJob domain model.
Tracks an execution of the cryptographic posture analysis pipeline against a Capture.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.enums import JobStatus, RiskBand

if TYPE_CHECKING:
    from app.models.capture import Capture
    from app.models.session import EmailSession
    from app.models.finding import Finding
    from app.models.timeline import TimelineEvent


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    capture_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("captures.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus),
        nullable=False,
        default=JobStatus.PENDING,
        index=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    options_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    total_sessions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    overall_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_band: Mapped[Optional[RiskBand]] = mapped_column(
        Enum(RiskBand), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    capture: Mapped["Capture"] = relationship("Capture", back_populates="jobs")

    sessions: Mapped[List["EmailSession"]] = relationship(
        "EmailSession",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="EmailSession.session_index",
    )

    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="job",
        cascade="all, delete-orphan",
    )

    timeline_events: Mapped[List["TimelineEvent"]] = relationship(
        "TimelineEvent",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="TimelineEvent.timestamp",
    )
