"""
Certificate domain models: Certificate and CertificateChain.
Stores parsed X.509 certificate attributes, validity relative to capture timestamp, and chain metrics.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

if TYPE_CHECKING:
    from app.models.session import EmailSession


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("email_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    certificate_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_server_cert: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    subject_dn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    issuer_dn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    not_before: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    not_after: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    public_key_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    public_key_size_bits: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_weak_signature: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    sha256_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    sha1_fingerprint: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)

    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_valid_at_capture: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    san_domains: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    raw_der_bytes: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    # ─── Relationships ────────────────────────────────────────────────────────
    session: Mapped["EmailSession"] = relationship(
        "EmailSession", back_populates="certificates"
    )


class CertificateChain(Base):
    """
    Certificate chain completeness and validation summary.
    """
    __tablename__ = "certificate_chains"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("email_sessions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    chain_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_chain_complete: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    validation_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UNCHECKED"
    )
    validation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    root_issuer_dn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    leaf_subject_dn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ─── Relationships ────────────────────────────────────────────────────────
    session: Mapped["EmailSession"] = relationship(
        "EmailSession", back_populates="certificate_chain"
    )
