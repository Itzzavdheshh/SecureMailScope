"""
Session domain models: EmailSession, StarttlsState, and TlsHandshake.
Captures per-TCP mail stream protocol characteristics, STARTTLS state transitions, and TLS handshakes.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.enums import ProtocolType, StarttlsStatus

if TYPE_CHECKING:
    from app.models.job import AnalysisJob
    from app.models.certificate import Certificate, CertificateChain
    from app.models.finding import Finding
    from app.models.timeline import TimelineEvent


class EmailSession(Base):
    __tablename__ = "email_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    session_index: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    client_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    client_port: Mapped[int] = mapped_column(Integer, nullable=False)
    server_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    server_port: Mapped[int] = mapped_column(Integer, nullable=False)

    protocol: Mapped[ProtocolType] = mapped_column(
        Enum(ProtocolType),
        nullable=False,
        default=ProtocolType.UNKNOWN,
        index=True,
    )
    is_tls_implicit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    starttls_state: Mapped[StarttlsStatus] = mapped_column(
        Enum(StarttlsStatus),
        nullable=False,
        default=StarttlsStatus.NOT_OBSERVED,
        index=True,
    )

    start_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_transferred: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )

    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # ─── Relationships ────────────────────────────────────────────────────────
    job: Mapped["AnalysisJob"] = relationship("AnalysisJob", back_populates="sessions")

    tls_handshake: Mapped[Optional["TlsHandshake"]] = relationship(
        "TlsHandshake",
        back_populates="session",
        uselist=False,
        cascade="all, delete-orphan",
    )

    certificates: Mapped[List["Certificate"]] = relationship(
        "Certificate",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="Certificate.certificate_index",
    )

    certificate_chain: Mapped[Optional["CertificateChain"]] = relationship(
        "CertificateChain",
        back_populates="session",
        uselist=False,
        cascade="all, delete-orphan",
    )

    starttls_details: Mapped[Optional["StarttlsState"]] = relationship(
        "StarttlsState",
        back_populates="session",
        uselist=False,
        cascade="all, delete-orphan",
    )

    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="session",
        cascade="all, delete-orphan",
    )

    timeline_events: Mapped[List["TimelineEvent"]] = relationship(
        "TimelineEvent",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="TimelineEvent.timestamp",
    )


class StarttlsState(Base):
    """
    Explicit STARTTLS state machine evidence.
    Tracks negotiation frames, command/response codes, and downgrade attempts.
    """
    __tablename__ = "starttls_states"

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

    observed_state: Mapped[StarttlsStatus] = mapped_column(
        Enum(StarttlsStatus),
        nullable=False,
        default=StarttlsStatus.NOT_OBSERVED,
    )
    advertised_in_frame: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    command_in_frame: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_in_frame: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_downgrade_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    state_details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ─── Relationships ────────────────────────────────────────────────────────
    session: Mapped["EmailSession"] = relationship(
        "EmailSession", back_populates="starttls_details"
    )


class TlsHandshake(Base):
    """
    TLS Handshake domain model.
    Stores evidence for ClientHello/ServerHello, cipher suites, key exchange, and FS.
    """
    __tablename__ = "tls_handshakes"

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

    client_hello_frame: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    server_hello_frame: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    offered_tls_versions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    negotiated_tls_version: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )

    client_cipher_suites: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    negotiated_cipher_suite: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True
    )

    key_exchange_group: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    key_exchange_bits: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_forward_secrecy: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    sni_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    alpn_protocols: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    handshake_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ATTEMPTED"
    )

    raw_client_hello_bytes: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )
    raw_server_hello_bytes: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    session: Mapped["EmailSession"] = relationship(
        "EmailSession", back_populates="tls_handshake"
    )
