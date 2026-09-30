"""
Timeline domain model.
Reconstructs chronological network sequence of events for a capture/session.
"""

import uuid
from typing import TYPE_CHECKING, Optional
from sqlalchemy import Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.enums import Severity

if TYPE_CHECKING:
    from app.models.job import AnalysisJob
    from app.models.session import EmailSession


class TimelineEvent(Base):
    """
    Chronological event timeline record.
    """
    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("email_sessions.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    timestamp: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    frame_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), nullable=False, default=Severity.INFO
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    job: Mapped["AnalysisJob"] = relationship("AnalysisJob", back_populates="timeline_events")
    session: Mapped[Optional["EmailSession"]] = relationship(
        "EmailSession", back_populates="timeline_events"
    )
