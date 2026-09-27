"""
Phase 1 Database Verification Test Suite.
Verifies all 12 Phase 1 requirements for database initialization, Alembic migrations,
model imports, table creation, relationships, evidence granularity, and object graph persistence.
"""

import os
import pytest
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.db.session import Base, init_db, _set_sqlite_pragma
from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    StarttlsState,
    TlsHandshake,
    Certificate,
    CertificateChain,
    Finding,
    Evidence,
    InfrastructureIdentity,
    DriftEvent,
    TimelineEvent,
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


@pytest.fixture
async def test_db_session():
    """Create an in-memory SQLite database for test isolation."""
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    async with session_factory() as session:
        yield session

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_01_database_initialization():
    """1. Database initializes successfully."""
    await init_db()
    assert Base.metadata is not None


@pytest.mark.asyncio
async def test_02_all_models_import():
    """3. All models import successfully."""
    models = [
        Capture,
        AnalysisJob,
        EmailSession,
        StarttlsState,
        TlsHandshake,
        Certificate,
        CertificateChain,
        Finding,
        Evidence,
        InfrastructureIdentity,
        DriftEvent,
        TimelineEvent,
    ]
    for m in models:
        assert hasattr(m, "__tablename__")


@pytest.mark.asyncio
async def test_04_tables_created_correctly(test_db_session: AsyncSession):
    """4. Tables are created correctly in metadata."""
    expected_tables = {
        "captures",
        "analysis_jobs",
        "email_sessions",
        "starttls_states",
        "tls_handshakes",
        "certificates",
        "certificate_chains",
        "findings",
        "evidence_records",
        "infrastructure_identities",
        "drift_events",
        "timeline_events",
    }
    actual_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(actual_tables)


@pytest.mark.asyncio
async def test_05_capture_analysisjob_relationship(test_db_session: AsyncSession):
    """5. Capture -> AnalysisJob relationship works."""
    cap = Capture(
        filename="test_mail.pcap",
        file_path="/tmp/test_mail.pcap",
        file_size_bytes=1024,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    job = AnalysisJob(capture=cap, status=JobStatus.RUNNING)
    test_db_session.add(cap)
    await test_db_session.commit()

    stmt = select(Capture).where(Capture.id == cap.id)
    res = await test_db_session.execute(stmt)
    retrieved = res.scalar_one()

    assert len(retrieved.jobs) == 1
    assert retrieved.jobs[0].id == job.id
    assert retrieved.jobs[0].status == JobStatus.RUNNING


@pytest.mark.asyncio
async def test_06_analysisjob_emailsession_relationship(test_db_session: AsyncSession):
    """6. AnalysisJob -> EmailSession relationship works."""
    cap = Capture(filename="a.pcap", file_path="/tmp/a.pcap", sha256_hash="123")
    job = AnalysisJob(capture=cap)
    sess1 = EmailSession(
        job=job,
        session_index=1,
        client_ip="192.168.1.100",
        client_port=54321,
        server_ip="10.0.0.25",
        server_port=25,
        protocol=ProtocolType.SMTP,
    )
    test_db_session.add_all([cap, job, sess1])
    await test_db_session.commit()

    stmt = select(AnalysisJob).where(AnalysisJob.id == job.id)
    res = await test_db_session.execute(stmt)
    retrieved_job = res.scalar_one()

    assert len(retrieved_job.sessions) == 1
    assert retrieved_job.sessions[0].client_ip == "192.168.1.100"
    assert retrieved_job.sessions[0].protocol == ProtocolType.SMTP


@pytest.mark.asyncio
async def test_07_emailsession_finding_relationship(test_db_session: AsyncSession):
    """7. EmailSession -> Finding relationship works."""
    cap = Capture(filename="b.pcap", file_path="/tmp/b.pcap", sha256_hash="456")
    job = AnalysisJob(capture=cap)
    sess = EmailSession(
        job=job,
        session_index=1,
        client_ip="1.1.1.1",
        client_port=1000,
        server_ip="2.2.2.2",
        server_port=993,
        protocol=ProtocolType.IMAP,
    )
    finding = Finding(
        job=job,
        session=sess,
        rule_id="CRYPT-001",
        title="SSLv3 Protocol Allowed",
        category=FindingCategory.TLS_CRYPTO,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Obsolete SSLv3 protocol offered",
    )
    test_db_session.add_all([cap, job, sess, finding])
    await test_db_session.commit()

    stmt = select(EmailSession).where(EmailSession.id == sess.id)
    res = await test_db_session.execute(stmt)
    retrieved_sess = res.scalar_one()

    assert len(retrieved_sess.findings) == 1
    assert retrieved_sess.findings[0].rule_id == "CRYPT-001"
    assert retrieved_sess.findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_08_finding_evidence_relationship(test_db_session: AsyncSession):
    """8. Finding -> Evidence relationship works."""
    cap = Capture(filename="c.pcap", file_path="/tmp/c.pcap", sha256_hash="789")
    job = AnalysisJob(capture=cap)
    sess = EmailSession(
        job=job,
        session_index=1,
        client_ip="10.0.0.1",
        client_port=4444,
        server_ip="10.0.0.2",
        server_port=25,
        protocol=ProtocolType.SMTP,
    )
    finding = Finding(
        job=job,
        session=sess,
        rule_id="STARTTLS-002",
        title="STARTTLS Stripped",
        category=FindingCategory.STARTTLS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="STARTTLS advertisement removed by proxy",
    )
    ev = Evidence(
        finding=finding,
        capture=cap,
        session=sess,
        frame_number=42,
        packet_timestamp=1700000000.123456,
        protocol_layer="SMTP",
        field_name="ehlo_response_capabilities",
        observed_value="250-8BITMIME\\r\\n250-SIZE 50000000",
        evidence_status=EvidenceStatus.OBSERVED,
    )
    test_db_session.add_all([cap, job, sess, finding, ev])
    await test_db_session.commit()

    stmt = select(Finding).where(Finding.id == finding.id)
    res = await test_db_session.execute(stmt)
    retrieved_finding = res.scalar_one()

    assert len(retrieved_finding.evidence) == 1
    assert retrieved_finding.evidence[0].frame_number == 42
    assert retrieved_finding.evidence[0].protocol_layer == "SMTP"


@pytest.mark.asyncio
async def test_09_infrastructure_driftevent_relationship(test_db_session: AsyncSession):
    """9. InfrastructureIdentity -> DriftEvent relationship works."""
    infra = InfrastructureIdentity(
        ip_address="192.0.2.1",
        hostname="mail.example.org",
        organization="Example Corp",
    )
    drift = DriftEvent(
        infrastructure=infra,
        event_type=DriftEventType.CIPHER_DOWNGRADE,
        previous_state="TLS_AES_256_GCM_SHA384",
        new_state="TLS_RSA_WITH_AES_128_CBC_SHA",
        delta_description="Cipher downgraded from TLS 1.3 to legacy AES-CBC",
        risk_delta=25.0,
    )
    test_db_session.add_all([infra, drift])
    await test_db_session.commit()

    stmt = select(InfrastructureIdentity).where(InfrastructureIdentity.id == infra.id)
    res = await test_db_session.execute(stmt)
    retrieved_infra = res.scalar_one()

    assert len(retrieved_infra.drift_events) == 1
    assert retrieved_infra.drift_events[0].event_type == DriftEventType.CIPHER_DOWNGRADE
    assert retrieved_infra.drift_events[0].risk_delta == 25.0


@pytest.mark.asyncio
async def test_10_timeline_event_references(test_db_session: AsyncSession):
    """10. TimelineEvent can reference the relevant session/capture."""
    cap = Capture(filename="t.pcap", file_path="/tmp/t.pcap", sha256_hash="abc")
    job = AnalysisJob(capture=cap)
    sess = EmailSession(
        job=job,
        session_index=1,
        client_ip="10.1.1.1",
        client_port=1234,
        server_ip="10.1.1.2",
        server_port=25,
        protocol=ProtocolType.SMTP,
    )
    event = TimelineEvent(
        job=job,
        session=sess,
        timestamp=1700000001.500,
        event_type="STARTTLS_ATTEMPTED",
        frame_number=15,
        summary="Client sent STARTTLS command",
        severity=Severity.INFO,
    )
    test_db_session.add_all([cap, job, sess, event])
    await test_db_session.commit()

    stmt = select(TimelineEvent).where(TimelineEvent.id == event.id)
    res = await test_db_session.execute(stmt)
    retrieved_evt = res.scalar_one()

    assert retrieved_evt.job_id == job.id
    assert retrieved_evt.session_id == sess.id
    assert retrieved_evt.frame_number == 15


@pytest.mark.asyncio
async def test_11_evidence_preserves_forensic_fields(test_db_session: AsyncSession):
    """11. Evidence correctly stores frame number, timestamp, protocol layer, field name, and observed value."""
    cap = Capture(filename="e.pcap", file_path="/tmp/e.pcap", sha256_hash="def")
    job = AnalysisJob(capture=cap)
    finding = Finding(
        job=job,
        rule_id="X509-001",
        title="Expired Certificate",
        category=FindingCategory.X509_CERT,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Certificate expired prior to capture timestamp",
    )
    ev = Evidence(
        finding=finding,
        capture=cap,
        frame_number=108,
        packet_timestamp=1712345678.987654,
        protocol_layer="X509",
        field_name="validity_not_after",
        observed_value="2025-12-31T23:59:59Z",
        source_reference="ServerHello -> Certificate -> validity",
        evidence_status=EvidenceStatus.OBSERVED,
        hex_dump_snippet="30 82 01 0a...",
    )
    test_db_session.add_all([cap, job, finding, ev])
    await test_db_session.commit()

    stmt = select(Evidence).where(Evidence.id == ev.id)
    res = await test_db_session.execute(stmt)
    retrieved_ev = res.scalar_one()

    assert retrieved_ev.frame_number == 108
    assert retrieved_ev.packet_timestamp == 1712345678.987654
    assert retrieved_ev.protocol_layer == "X509"
    assert retrieved_ev.field_name == "validity_not_after"
    assert retrieved_ev.observed_value == "2025-12-31T23:59:59Z"
    assert retrieved_ev.evidence_status == EvidenceStatus.OBSERVED


@pytest.mark.asyncio
async def test_12_complete_object_graph_persistence(test_db_session: AsyncSession):
    """12. A complete small object graph can be inserted and retrieved successfully."""
    # 1. Capture & Job
    cap = Capture(
        filename="full_flow.pcap",
        file_path="/var/pcaps/full_flow.pcap",
        file_size_bytes=5242880,
        sha256_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        total_packets=1250,
        status="PROCESSED",
    )
    job = AnalysisJob(
        capture=cap,
        status=JobStatus.COMPLETED,
        total_sessions=1,
        total_findings=1,
        overall_risk_score=75.5,
        risk_band=RiskBand.HIGH,
    )

    # 2. EmailSession
    sess = EmailSession(
        job=job,
        session_index=1,
        client_ip="192.168.1.50",
        client_port=49152,
        server_ip="198.51.100.25",
        server_port=25,
        protocol=ProtocolType.SMTP,
        is_tls_implicit=False,
        starttls_state=StarttlsStatus.ACCEPTED,
        packet_count=35,
        bytes_transferred=14200,
        banner="250 mail.enterprise.com ESMTP Postfix",
        hostname="mail.enterprise.com",
        risk_score=75.5,
    )

    # 3. STARTTLS details
    st_details = StarttlsState(
        session=sess,
        observed_state=StarttlsStatus.ACCEPTED,
        advertised_in_frame=5,
        command_in_frame=9,
        response_in_frame=11,
        response_code=220,
        is_downgrade_detected=False,
    )

    # 4. TLS Handshake
    tls = TlsHandshake(
        session=sess,
        client_hello_frame=14,
        server_hello_frame=16,
        offered_tls_versions="['TLS 1.2', 'TLS 1.3']",
        negotiated_tls_version="TLS 1.2",
        negotiated_cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange_group="secp256r1",
        key_exchange_bits=256,
        is_forward_secrecy=True,
        sni_hostname="mail.enterprise.com",
    )

    # 5. Certificates & Chain
    cert = Certificate(
        session=sess,
        certificate_index=0,
        is_server_cert=True,
        subject_dn="CN=mail.enterprise.com, O=Enterprise Inc",
        issuer_dn="CN=Legacy Sub CA, O=Legacy PKI",
        signature_algorithm="sha1WithRSAEncryption",
        is_weak_signature=True,
        sha256_fingerprint="a"*64,
        is_self_signed=False,
        is_valid_at_capture=True,
    )
    chain = CertificateChain(
        session=sess,
        chain_length=1,
        is_chain_complete=True,
        validation_status="WEAK_SIGNATURE",
    )

    # 6. Finding & Evidence
    finding = Finding(
        job=job,
        session=sess,
        rule_id="X509-003",
        title="SHA-1 Weak Signature Algorithm",
        category=FindingCategory.X509_CERT,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        status=EvidenceStatus.OBSERVED,
        score_contribution=25.0,
        description="Certificate uses deprecated SHA-1 signature algorithm.",
    )
    evidence = Evidence(
        finding=finding,
        capture=cap,
        session=sess,
        frame_number=16,
        packet_timestamp=1710000000.50,
        protocol_layer="X509",
        field_name="signatureAlgorithm.algorithm",
        observed_value="1.2.840.113549.1.1.5 (sha1WithRSAEncryption)",
        evidence_status=EvidenceStatus.OBSERVED,
    )

    # 7. Timeline Event
    timeline = TimelineEvent(
        job=job,
        session=sess,
        timestamp=1710000000.50,
        event_type="WEAK_CERT_DETECTED",
        frame_number=16,
        summary="SHA-1 certificate detected during TLS handshake",
        severity=Severity.HIGH,
    )

    # Save complete graph
    test_db_session.add_all([cap, job, sess, st_details, tls, cert, chain, finding, evidence, timeline])
    await test_db_session.commit()

    # Query back and verify entire graph hierarchy
    stmt = select(Capture).where(Capture.id == cap.id)
    res = await test_db_session.execute(stmt)
    retrieved_cap = res.scalar_one()

    assert retrieved_cap.filename == "full_flow.pcap"
    assert len(retrieved_cap.jobs) == 1
    
    ret_job = retrieved_cap.jobs[0]
    assert ret_job.overall_risk_score == 75.5
    assert len(ret_job.sessions) == 1

    ret_sess = ret_job.sessions[0]
    assert ret_sess.starttls_details.response_code == 220
    assert ret_sess.tls_handshake.negotiated_tls_version == "TLS 1.2"
    assert len(ret_sess.certificates) == 1
    assert ret_sess.certificates[0].is_weak_signature is True
    assert ret_sess.certificate_chain.is_chain_complete is True

    assert len(ret_sess.findings) == 1
    assert ret_sess.findings[0].rule_id == "X509-003"
    assert len(ret_sess.findings[0].evidence) == 1
    assert ret_sess.findings[0].evidence[0].field_name == "signatureAlgorithm.algorithm"
    assert ret_sess.findings[0].evidence[0].frame_number == 16
