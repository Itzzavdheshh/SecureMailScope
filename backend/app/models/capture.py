"""
Capture domain model.
Represents an ingested PCAP/PCAPNG network traffic file.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import BigInteger, DateTime, String, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.job import AnalysisJob


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    total_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    capture_start_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    capture_end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="UPLOADED")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    jobs: Mapped[List["AnalysisJob"]] = relationship(
        "AnalysisJob",
        back_populates="capture",
        cascade="all, delete-orphan",
        order_by="AnalysisJob.created_at.desc()",
    )
