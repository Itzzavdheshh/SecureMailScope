"""
Query Service for Database Filtering, Pagination, and Aggregation.
Provides reusable, deterministic query helpers for REST API routers and Reporting engine without duplicating logic.
"""

import math
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    TlsHandshake,
    Certificate,
    CertificateChain,
    StarttlsState,
    Finding,
    Evidence,
    InfrastructureIdentity,
    DriftEvent,
    TimelineEvent,
    Severity,
    FindingCategory,
    Confidence,
    RiskBand,
    JobStatus,
    DriftEventType,
    ProtocolType,
    StarttlsStatus,
)
from app.schemas.risk import RiskSummaryResponse


async def get_paginated_captures(
    db: AsyncSession, page: int = 1, page_size: int = 50
) -> Tuple[List[Capture], int]:
    """Retrieve paginated Capture records ordered by created_at DESC."""
    count_stmt = select(func.count(Capture.id))
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(Capture)
        .order_by(Capture.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_paginated_jobs(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    capture_id: Optional[str] = None,
    status: Optional[JobStatus] = None,
) -> Tuple[List[AnalysisJob], int]:
    """Retrieve paginated AnalysisJob records."""
    query = select(AnalysisJob)
    if capture_id:
        query = query.where(AnalysisJob.capture_id == capture_id)
    if status:
        query = query.where(AnalysisJob.status == status)

    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = query.order_by(AnalysisJob.created_at.desc()).offset(offset).limit(page_size)
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_latest_completed_job(
    db: AsyncSession, capture_id: str
) -> Optional[AnalysisJob]:
    """Return the newest completed analysis for a capture, never a pending/failed run."""
    stmt = (
        select(AnalysisJob)
        .where(
            AnalysisJob.capture_id == capture_id,
            AnalysisJob.status == JobStatus.COMPLETED,
        )
        .order_by(AnalysisJob.created_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_paginated_sessions(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    capture_id: Optional[str] = None,
    job_id: Optional[str] = None,
    protocol: Optional[str] = None,
    server_ip: Optional[str] = None,
    server_port: Optional[int] = None,
    hostname: Optional[str] = None,
    tls_version: Optional[str] = None,
    cipher: Optional[str] = None,
    starttls_state: Optional[str] = None,
    min_risk: Optional[float] = None,
    max_risk: Optional[float] = None,
) -> Tuple[List[EmailSession], int]:
    """Retrieve paginated EmailSession records with flexible filtering."""
    query = select(EmailSession).options(
        selectinload(EmailSession.tls_handshake),
        selectinload(EmailSession.starttls_details),
    )

    if job_id:
        query = query.where(EmailSession.job_id == job_id)
    elif capture_id:
        # Join through jobs
        query = query.join(AnalysisJob, EmailSession.job_id == AnalysisJob.id).where(
            AnalysisJob.capture_id == capture_id
        )

    if protocol:
        query = query.where(EmailSession.protocol == protocol)
    if server_ip:
        query = query.where(EmailSession.server_ip == server_ip)
    if server_port is not None:
        query = query.where(EmailSession.server_port == server_port)
    if hostname:
        query = query.where(EmailSession.hostname.ilike(f"%{hostname}%"))
    if starttls_state:
        query = query.where(EmailSession.starttls_state == starttls_state)
    if min_risk is not None:
        query = query.where(EmailSession.risk_score >= min_risk)
    if max_risk is not None:
        query = query.where(EmailSession.risk_score <= max_risk)

    if tls_version or cipher:
        query = query.join(TlsHandshake, EmailSession.id == TlsHandshake.session_id)
        if tls_version:
            query = query.where(TlsHandshake.negotiated_tls_version == tls_version)
        if cipher:
            query = query.where(TlsHandshake.negotiated_cipher_suite.ilike(f"%{cipher}%"))

    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = query.order_by(EmailSession.session_index.asc()).offset(offset).limit(page_size)
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_session_by_id(db: AsyncSession, session_id: str) -> Optional[EmailSession]:
    """Retrieve EmailSession by ID with eager loaded relationships."""
    stmt = (
        select(EmailSession)
        .options(
            selectinload(EmailSession.tls_handshake),
            selectinload(EmailSession.certificates),
            selectinload(EmailSession.certificate_chain),
            selectinload(EmailSession.starttls_details),
            selectinload(EmailSession.findings).selectinload(Finding.evidence),
        )
        .where(EmailSession.id == session_id)
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def get_paginated_findings(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    job_id: Optional[str] = None,
    session_id: Optional[str] = None,
    capture_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    confidence: Optional[str] = None,
    rule_id: Optional[str] = None,
) -> Tuple[List[Finding], int]:
    """Retrieve paginated Finding records with filters and eager loaded evidence."""
    query = select(Finding).options(selectinload(Finding.evidence))

    if session_id:
        query = query.where(Finding.session_id == session_id)
    if job_id:
        query = query.where(Finding.job_id == job_id)
    elif capture_id:
        query = query.join(AnalysisJob, Finding.job_id == AnalysisJob.id).where(
            AnalysisJob.capture_id == capture_id
        )

    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if confidence:
        query = query.where(Finding.confidence == confidence)
    if rule_id:
        query = query.where(Finding.rule_id == rule_id)

    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = query.order_by(Finding.created_at.desc()).offset(offset).limit(page_size)
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_finding_by_id(db: AsyncSession, finding_id: str) -> Optional[Finding]:
    """Retrieve Finding by ID with eager loaded evidence."""
    stmt = (
        select(Finding)
        .options(selectinload(Finding.evidence))
        .where(Finding.id == finding_id)
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def get_paginated_evidence(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    finding_id: Optional[str] = None,
    job_id: Optional[str] = None,
    session_id: Optional[str] = None,
    capture_id: Optional[str] = None,
    frame_number: Optional[int] = None,
    protocol_layer: Optional[str] = None,
    field_name: Optional[str] = None,
) -> Tuple[List[Evidence], int]:
    """Retrieve paginated Evidence records with forensic field filters."""
    query = select(Evidence)

    if finding_id:
        query = query.where(Evidence.finding_id == finding_id)
    if job_id:
        query = query.join(Finding, Evidence.finding_id == Finding.id).where(
            Finding.job_id == job_id
        )
    if session_id:
        query = query.where(Evidence.session_id == session_id)
    if capture_id:
        query = query.where(Evidence.capture_id == capture_id)
    if frame_number is not None:
        query = query.where(Evidence.frame_number == frame_number)
    if protocol_layer:
        query = query.where(Evidence.protocol_layer == protocol_layer)
    if field_name:
        query = query.where(Evidence.field_name == field_name)

    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = query.order_by(Evidence.frame_number.asc()).offset(offset).limit(page_size)
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_evidence_by_id(db: AsyncSession, evidence_id: str) -> Optional[Evidence]:
    """Retrieve Evidence by ID."""
    stmt = select(Evidence).where(Evidence.id == evidence_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def get_paginated_infrastructure(
    db: AsyncSession, page: int = 1, page_size: int = 50
) -> Tuple[List[InfrastructureIdentity], int]:
    """Retrieve paginated InfrastructureIdentity records."""
    query = select(InfrastructureIdentity).options(
        selectinload(InfrastructureIdentity.drift_events)
    )

    count_stmt = select(func.count(InfrastructureIdentity.id))
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = query.order_by(InfrastructureIdentity.last_seen_at.desc()).offset(offset).limit(page_size)
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_infrastructure_by_id(
    db: AsyncSession, identity_id: str
) -> Optional[InfrastructureIdentity]:
    """Retrieve InfrastructureIdentity by ID with drift events."""
    stmt = (
        select(InfrastructureIdentity)
        .options(selectinload(InfrastructureIdentity.drift_events))
        .where(InfrastructureIdentity.id == identity_id)
    )
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def get_paginated_drifts(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    infrastructure_id: Optional[str] = None,
    job_id: Optional[str] = None,
    capture_id: Optional[str] = None,
    event_type: Optional[str] = None,
) -> Tuple[List[DriftEvent], int]:
    """Retrieve paginated DriftEvent records."""
    query = select(DriftEvent)

    if infrastructure_id:
        query = query.where(DriftEvent.infrastructure_id == infrastructure_id)
    if job_id:
        query = query.where(DriftEvent.job_id == job_id)
    if capture_id:
        query = query.where(DriftEvent.capture_id == capture_id)
    if event_type:
        query = query.where(DriftEvent.event_type == event_type)

    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    offset = (page - 1) * page_size
    stmt = query.order_by(DriftEvent.detected_at.desc()).offset(offset).limit(page_size)
    res = await db.execute(stmt)
    items = list(res.scalars().all())
    return items, total


async def get_drift_by_id(db: AsyncSession, drift_id: str) -> Optional[DriftEvent]:
    """Retrieve DriftEvent by ID."""
    stmt = select(DriftEvent).where(DriftEvent.id == drift_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def get_timeline_events(
    db: AsyncSession, session_id: Optional[str] = None, job_id: Optional[str] = None
) -> List[TimelineEvent]:
    """Retrieve TimelineEvent records ordered deterministically by timestamp and frame_number."""
    query = select(TimelineEvent)
    if session_id:
        query = query.where(TimelineEvent.session_id == session_id)
    elif job_id:
        query = query.where(TimelineEvent.job_id == job_id)
    else:
        return []

    stmt = query.order_by(TimelineEvent.timestamp.asc(), TimelineEvent.frame_number.asc())
    res = await db.execute(stmt)
    return list(res.scalars().all())


async def get_risk_summary(
    db: AsyncSession, capture_id: Optional[str] = None, job_id: Optional[str] = None
) -> Optional[RiskSummaryResponse]:
    """
    Calculate risk summary posture metrics using existing Phase 5 risk score calculations.
    """
    target_job: Optional[AnalysisJob] = None

    if job_id:
        stmt = select(AnalysisJob).where(AnalysisJob.id == job_id)
        res = await db.execute(stmt)
        target_job = res.scalar_one_or_none()
        if target_job and target_job.status != JobStatus.COMPLETED:
            return None
    elif capture_id:
        target_job = await get_latest_completed_job(db, capture_id)

    if not target_job:
        return None

    # Retrieve sessions count, findings, and drift count
    sess_stmt = select(EmailSession).where(EmailSession.job_id == target_job.id)
    sess_res = await db.execute(sess_stmt)
    sessions = list(sess_res.scalars().all())

    find_stmt = select(Finding).where(Finding.job_id == target_job.id)
    find_res = await db.execute(find_stmt)
    findings = list(find_res.scalars().all())

    drift_stmt = select(func.count(DriftEvent.id)).where(DriftEvent.job_id == target_job.id)
    drift_res = await db.execute(drift_stmt)
    drift_count = drift_res.scalar() or 0

    sev_dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_dist[sev_key] = sev_dist.get(sev_key, 0) + 1

    high_risk_count = sum(1 for s in sessions if (s.risk_score or 0.0) >= 40.0)

    overall_score = target_job.overall_risk_score or 0.0
    band = target_job.risk_band or (
        RiskBand.CRITICAL if overall_score >= 80.0 else
        RiskBand.HIGH if overall_score >= 60.0 else
        RiskBand.MEDIUM if overall_score >= 40.0 else
        RiskBand.LOW if overall_score >= 20.0 else
        RiskBand.SECURE
    )

    return RiskSummaryResponse(
        capture_id=target_job.capture_id,
        job_id=target_job.id,
        overall_risk_score=overall_score,
        risk_band=band,
        total_sessions=len(sessions),
        total_findings=len(findings),
        severity_distribution=sev_dist,
        drift_count=drift_count,
        high_risk_session_count=high_risk_count,
    )
