"""
Infrastructure and Drift domain models.
Database foundation for tracking host cryptographic security postures across captures over time.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.enums import DriftEventType, RiskBand


class InfrastructureIdentity(Base):
    """
    Tracked mail server node or endpoint host.
    """
    __tablename__ = "infrastructure_identities"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, nullable=False, index=True
    )
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, index=True
    )
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=25)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, default="SMTP")
    identity_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    active_profile_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    current_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    current_risk_band: Mapped[Optional[RiskBand]] = mapped_column(
        Enum(RiskBand), nullable=True
    )

    last_evaluated_job_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    drift_events: Mapped[List["DriftEvent"]] = relationship(
        "DriftEvent",
        back_populates="infrastructure",
        cascade="all, delete-orphan",
        order_by="DriftEvent.detected_at.desc()",
    )


class DriftEvent(Base):
    """
    Cryptographic configuration drift detection event.
    """
    __tablename__ = "drift_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    infrastructure_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("infrastructure_identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    capture_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("captures.id", ondelete="SET NULL"),
        nullable=True,
    )
    job_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )

    event_type: Mapped[DriftEventType] = mapped_column(
        Enum(DriftEventType), nullable=False
    )
    previous_state: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_state: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    delta_description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_delta: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    infrastructure: Mapped["InfrastructureIdentity"] = relationship(
        "InfrastructureIdentity", back_populates="drift_events"
    )
