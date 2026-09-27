"""
Phase 7 Test Suite — Reports & Backend REST API.
Validates production REST API (v1), schema serialization, query filtering, pagination bounds,
deterministic report generation engine (JSON, HTML, PDF), evidence lineage, security constraints,
and OpenAPI documentation schema.
"""

import io
import json
import pytest
from datetime import datetime, timezone
from typing import Dict, List
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config import settings
from app.db.session import Base
from app.main import app
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
    StarttlsStatus,
    ProtocolType,
    Severity,
    Confidence,
    EvidenceStatus,
    FindingCategory,
    RiskBand,
    DriftEventType,
)
from app.reports.report_generator import (
    build_report_data_graph,
    generate_json_report,
    generate_html_report,
    generate_pdf_report,
)


@pytest.fixture(autouse=True)
async def setup_test_environment(tmp_path):
    """Override upload_dir and database_url to isolated temp folder/file for each test."""
    original_upload_dir = settings.upload_dir
    original_db_url = settings.database_url

    settings.upload_dir = str(tmp_path / "uploads")
    db_file = tmp_path / "test.db"
    settings.database_url = f"sqlite+aiosqlite:///{db_file}"

    from app.db import session as db_session_module

    db_session_module.engine = create_async_engine(
        settings.database_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False},
    )
    db_session_module.AsyncSessionLocal = async_sessionmaker(
        bind=db_session_module.engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    async with db_session_module.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield

    await db_session_module.engine.dispose()
    settings.upload_dir = original_upload_dir
    settings.database_url = original_db_url


@pytest.fixture
async def sample_db_data():
    """Populate isolated test database with a complete forensic object graph."""
    from app.db.session import AsyncSessionLocal

    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        capture = Capture(
            id="cap-test-12345678",
            filename="sample_forensic.pcap",
            file_path="/uploads/sample_forensic.pcap",
            file_size_bytes=1048576,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            total_packets=125,
            created_at=now,
        )
        db.add(capture)

        job = AnalysisJob(
            id="job-test-87654321",
            capture_id=capture.id,
            status="COMPLETED",
            created_at=now,
            completed_at=now,
            overall_risk_score=75.5,
            risk_band=RiskBand.HIGH,
        )
        db.add(job)

        session1 = EmailSession(
            id="sess-test-1",
            job_id=job.id,
            session_index=1,
            client_ip="192.168.1.100",
            client_port=49152,
            server_ip="192.168.1.25",
            server_port=25,
            protocol=ProtocolType.SMTP,
            starttls_state=StarttlsStatus.ACCEPTED,
            is_tls_implicit=False,
            risk_score=75.5,
            packet_count=20,
            bytes_transferred=4096,
            banner="220 mail.example.com ESMTP Postfix",
            hostname="mail.example.com",
            start_time=now,
            end_time=now,
        )
        session2 = EmailSession(
            id="sess-test-2",
            job_id=job.id,
            session_index=2,
            client_ip="192.168.1.101",
            client_port=49153,
            server_ip="192.168.1.25",
            server_port=143,
            protocol=ProtocolType.IMAP,
            starttls_state=StarttlsStatus.NOT_OBSERVED,
            is_tls_implicit=False,
            risk_score=15.0,
            packet_count=10,
            bytes_transferred=2048,
            hostname="mail.example.com",
            start_time=now,
            end_time=now,
        )
        db.add_all([session1, session2])

        handshake = TlsHandshake(
            id="tls-test-1",
            session_id=session1.id,
            client_hello_frame=5,
            server_hello_frame=7,
            negotiated_tls_version="TLS 1.0",
            negotiated_cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
            is_forward_secrecy=False,
            key_exchange_group="RSA",
        )
        db.add(handshake)

        cert = Certificate(
            id="cert-test-1",
            session_id=session1.id,
            sha256_fingerprint="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            subject_dn="CN=mail.example.com, O=Example Corp",
            issuer_dn="CN=Example Intermediate CA",
            not_before=now,
            not_after=now,
            is_self_signed=False,
            is_valid_at_capture=True,
            signature_algorithm="sha1WithRSAEncryption",
            public_key_type="RSA",
            public_key_size_bits=1024,
            serial_number="123456789",
        )
        db.add(cert)

        finding1 = Finding(
            id="find-test-1",
            job_id=job.id,
            session_id=session1.id,
            rule_id="CRYPT-001",
            title="Deprecated TLS Version (TLS 1.0)",
            category=FindingCategory.TLS_CRYPTO,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            score_contribution=40.0,
            description="Negotiated TLS 1.0 is deprecated and vulnerable to BEAST attacks.",
            remediation_recommendation="Configure server to require TLS 1.2 or TLS 1.3.",
            created_at=now,
        )
        finding2 = Finding(
            id="find-test-2",
            job_id=job.id,
            session_id=session1.id,
            rule_id="X509-001",
            title="Weak Signature Algorithm (SHA-1)",
            category=FindingCategory.X509_CERT,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            score_contribution=35.5,
            description="Certificate relies on deprecated SHA-1 signature algorithm.",
            remediation_recommendation="Reissue certificate with SHA-256 or stronger.",
            created_at=now,
        )
        db.add_all([finding1, finding2])

        evidence1 = Evidence(
            id="ev-test-1",
            finding_id=finding1.id,
            session_id=session1.id,
            capture_id=capture.id,
            frame_number=7,
            packet_timestamp=1770000000.0,
            protocol_layer="TLS",
            field_name="tls.handshake.version",
            observed_value="0x0301 (TLS 1.0)",
            hex_dump_snippet="0301",
            evidence_status=EvidenceStatus.OBSERVED,
        )
        db.add(evidence1)

        infra = InfrastructureIdentity(
            id="infra-test-1",
            ip_address="192.168.1.25",
            hostname="mail.example.com",
            first_seen_at=now,
            last_seen_at=now,
            current_risk_score=75.5,
            current_risk_band=RiskBand.HIGH,
            last_evaluated_job_id=job.id,
        )
        db.add(infra)

        drift = DriftEvent(
            id="drift-test-1",
            infrastructure_id=infra.id,
            job_id=job.id,
            capture_id=capture.id,
            event_type=DriftEventType.TLS_VERSION_DOWNGRADE,
            delta_description="TLS version downgraded from TLS 1.2 to TLS 1.0",
            previous_state='{"tls_version": "TLS 1.2"}',
            new_state='{"tls_version": "TLS 1.0"}',
            risk_delta=30.0,
            detected_at=now,
        )
        db.add(drift)

        tm1 = TimelineEvent(
            id="tm-test-1",
            job_id=job.id,
            session_id=session1.id,
            timestamp=1770000000.0,
            frame_number=1,
            event_type="TCP_CONNECT",
            summary="TCP handshake established with 192.168.1.25:25",
            severity=Severity.INFO,
        )
        tm2 = TimelineEvent(
            id="tm-test-2",
            job_id=job.id,
            session_id=session1.id,
            timestamp=1770000001.0,
            frame_number=5,
            event_type="TLS_CLIENT_HELLO",
            summary="ClientHello offered TLS 1.2, TLS 1.0",
            severity=Severity.INFO,
        )
        db.add_all([tm1, tm2])

        await db.commit()

    return {"capture_id": capture.id, "job_id": job.id, "session_id": session1.id}


# ─── PART A — REST API TESTS ──────────────────────────────────────────────────

@pytest.mark.anyio
async def test_v1_captures_list_and_detail(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/captures and GET /api/v1/captures/{id}."""
    resp = await client.get("/api/v1/captures")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == sample_db_data["capture_id"]

    cap_id = sample_db_data["capture_id"]
    resp_detail = await client.get(f"/api/v1/captures/{cap_id}")
    assert resp_detail.status_code == 200
    detail = resp_detail.json()
    assert detail["filename"] == "sample_forensic.pcap"
    assert detail["sha256_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.anyio
async def test_v1_captures_not_found(client: AsyncClient):
    """Test 404 for missing capture."""
    resp = await client.get("/api/v1/captures/non-existent-cap-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_v1_jobs_list_and_detail(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/jobs and GET /api/v1/jobs/{id}."""
    resp = await client.get("/api/v1/jobs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == sample_db_data["job_id"]

    job_id = sample_db_data["job_id"]
    resp_detail = await client.get(f"/api/v1/jobs/{job_id}")
    assert resp_detail.status_code == 200
    assert resp_detail.json()["status"] == "COMPLETED"


@pytest.mark.anyio
async def test_v1_jobs_not_found(client: AsyncClient):
    """Test 404 for missing job."""
    resp = await client.get("/api/v1/jobs/non-existent-job-id")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_v1_sessions_list_and_filtering(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/sessions with protocol and risk filters."""
    # List all
    resp = await client.get("/api/v1/sessions")
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    # Filter by protocol=SMTP
    resp_smtp = await client.get("/api/v1/sessions?protocol=SMTP")
    assert resp_smtp.status_code == 200
    assert resp_smtp.json()["total"] == 1
    assert resp_smtp.json()["items"][0]["protocol"] == "SMTP"

    # Filter by min_risk=50.0
    resp_risk = await client.get("/api/v1/sessions?min_risk=50.0")
    assert resp_risk.status_code == 200
    assert resp_risk.json()["total"] == 1
    assert resp_risk.json()["items"][0]["risk_score"] == 75.5


@pytest.mark.anyio
async def test_v1_session_detail_and_not_found(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/sessions/{id} and 404 behavior."""
    sess_id = sample_db_data["session_id"]
    resp = await client.get(f"/api/v1/sessions/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["client_ip"] == "192.168.1.100"
    assert data["tls_handshake"]["negotiated_tls_version"] == "TLS 1.0"

    resp_404 = await client.get("/api/v1/sessions/non-existent-sess")
    assert resp_404.status_code == 404


@pytest.mark.anyio
async def test_v1_findings_list_and_filtering(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/findings with severity and category filters."""
    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    resp_crit = await client.get("/api/v1/findings?severity=HIGH")
    assert resp_crit.status_code == 200
    assert resp_crit.json()["total"] == 2

    resp_cat = await client.get("/api/v1/findings?category=TLS_CRYPTO")
    assert resp_cat.status_code == 200
    assert resp_cat.json()["total"] == 1
    assert resp_cat.json()["items"][0]["rule_id"] == "CRYPT-001"


@pytest.mark.anyio
async def test_v1_finding_detail_and_not_found(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/findings/{id}."""
    resp = await client.get("/api/v1/findings/find-test-1")
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "CRYPT-001"

    resp_404 = await client.get("/api/v1/findings/non-existent-finding")
    assert resp_404.status_code == 404


@pytest.mark.anyio
async def test_v1_evidence_list_and_detail(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/evidence and GET /api/v1/evidence/{id}."""
    resp = await client.get("/api/v1/evidence?protocol_layer=TLS")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["field_name"] == "tls.handshake.version"

    resp_detail = await client.get("/api/v1/evidence/ev-test-1")
    assert resp_detail.status_code == 200
    assert resp_detail.json()["observed_value"] == "0x0301 (TLS 1.0)"

    resp_404 = await client.get("/api/v1/evidence/non-existent-ev")
    assert resp_404.status_code == 404


@pytest.mark.anyio
async def test_v1_infrastructure_list_and_detail(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/infrastructure and GET /api/v1/infrastructure/{id}."""
    resp = await client.get("/api/v1/infrastructure")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    resp_detail = await client.get("/api/v1/infrastructure/infra-test-1")
    assert resp_detail.status_code == 200
    assert resp_detail.json()["ip_address"] == "192.168.1.25"


@pytest.mark.anyio
async def test_v1_drifts_list_and_detail(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/drifts and GET /api/v1/drifts/{id}."""
    resp = await client.get("/api/v1/drifts")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["event_type"] == "TLS_VERSION_DOWNGRADE"

    resp_detail = await client.get("/api/v1/drifts/drift-test-1")
    assert resp_detail.status_code == 200
    assert resp_detail.json()["risk_delta"] == 30.0

    resp_404 = await client.get("/api/v1/drifts/non-existent-drift")
    assert resp_404.status_code == 404


@pytest.mark.anyio
async def test_v1_timeline_events(client: AsyncClient, sample_db_data):
    """Test job timeline and session timeline endpoints."""
    job_id = sample_db_data["job_id"]
    resp_job_tm = await client.get(f"/api/v1/jobs/{job_id}/timeline")
    assert resp_job_tm.status_code == 200
    job_events = resp_job_tm.json()
    assert len(job_events) == 2
    assert job_events[0]["event_type"] == "TCP_CONNECT"
    assert job_events[1]["event_type"] == "TLS_CLIENT_HELLO"

    sess_id = sample_db_data["session_id"]
    resp_sess_tm = await client.get(f"/api/v1/sessions/{sess_id}/timeline")
    assert resp_sess_tm.status_code == 200
    assert len(resp_sess_tm.json()) == 2


@pytest.mark.anyio
async def test_v1_risk_posture_summary(client: AsyncClient, sample_db_data):
    """Test risk posture summary endpoints."""
    cap_id = sample_db_data["capture_id"]
    resp = await client.get(f"/api/v1/captures/{cap_id}/risk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_risk_score"] == 75.5
    assert data["risk_band"] == "HIGH"
    assert data["total_sessions"] == 2
    assert data["total_findings"] == 2
    assert data["severity_distribution"]["HIGH"] == 2
    assert data["drift_count"] == 1

    job_id = sample_db_data["job_id"]
    resp_job = await client.get(f"/api/v1/jobs/{job_id}/risk")
    assert resp_job.status_code == 200


@pytest.mark.anyio
async def test_v1_pagination_bounds(client: AsyncClient):
    """Test page_size bounds validation (le=100 limit)."""
    resp = await client.get("/api/v1/sessions?page_size=200")
    assert resp.status_code == 422  # FastAPI validation error


# ─── PART B — REPORT GENERATION TESTS ─────────────────────────────────────────

@pytest.mark.anyio
async def test_v1_reports_json_format(client: AsyncClient, sample_db_data):
    """Test JSON report generation via API."""
    job_id = sample_db_data["job_id"]
    resp = await client.get(f"/api/v1/reports/{job_id}?format=json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    data = resp.json()

    assert data["executive_summary"]["overall_risk_score"] == 75.5
    assert len(data["findings"]) == 2
    assert data["findings"][0]["rule_id"] in ["CRYPT-001", "X509-001"]
    assert len(data["drifts"]) == 1
    assert data["drifts"][0]["event_type"] == "TLS_VERSION_DOWNGRADE"


@pytest.mark.anyio
async def test_v1_reports_html_format(client: AsyncClient, sample_db_data):
    """Test HTML report generation via API."""
    job_id = sample_db_data["job_id"]
    resp = await client.get(f"/api/v1/reports/{job_id}?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    html = resp.text

    assert "<!DOCTYPE html>" in html
    assert "SecureMailScope Investigation Report" in html
    assert "Deprecated TLS Version (TLS 1.0)" in html
    assert "sample_forensic.pcap" in html


@pytest.mark.anyio
async def test_v1_reports_pdf_format(client: AsyncClient, sample_db_data):
    """Test PDF report generation via API."""
    job_id = sample_db_data["job_id"]
    resp = await client.get(f"/api/v1/reports/{job_id}?format=pdf")
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    pdf_bytes = resp.content

    # Check standard PDF magic header
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 500


@pytest.mark.anyio
async def test_v1_capture_report_endpoint(client: AsyncClient, sample_db_data):
    """Test GET /api/v1/captures/{capture_id}/report."""
    cap_id = sample_db_data["capture_id"]
    resp = await client.get(f"/api/v1/captures/{cap_id}/report?format=json")
    assert resp.status_code == 200
    assert resp.json()["capture"]["filename"] == "sample_forensic.pcap"


@pytest.mark.anyio
async def test_v1_reports_invalid_format(client: AsyncClient, sample_db_data):
    """Test invalid report format returns 400 Bad Request."""
    job_id = sample_db_data["job_id"]
    resp = await client.get(f"/api/v1/reports/{job_id}?format=xml")
    assert resp.status_code == 400
    assert "supported formats are: json, html, pdf" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_v1_reports_not_found(client: AsyncClient):
    """Test missing job/capture returns 404."""
    resp = await client.get("/api/v1/reports/non-existent-job?format=json")
    assert resp.status_code == 404

    resp_cap = await client.get("/api/v1/captures/non-existent-cap/report?format=json")
    assert resp_cap.status_code == 404


# ─── PART C — FORENSIC & SECURITY CONSTRAINTS ─────────────────────────────────

@pytest.mark.anyio
async def test_evidence_lineage_preservation(client: AsyncClient, sample_db_data):
    """Verify evidence lineage: Finding -> Evidence -> Frame -> Layer -> Field -> Observed Value."""
    job_id = sample_db_data["job_id"]
    resp = await client.get(f"/api/v1/reports/{job_id}?format=json")
    data = resp.json()

    finding = next(f for f in data["findings"] if f["rule_id"] == "CRYPT-001")
    assert len(finding["evidence"]) > 0
    ev = finding["evidence"][0]
    assert ev["frame_number"] == 7
    assert ev["protocol_layer"] == "TLS"
    assert ev["field_name"] == "tls.handshake.version"
    assert ev["observed_value"] == "0x0301 (TLS 1.0)"


@pytest.mark.anyio
async def test_report_insufficient_evidence_representation():
    """Verify factual limitation language when evidence is missing."""
    dummy_data = {
        "report_metadata": {"report_id": "REP-1"},
        "capture": {"filename": "test.pcap"},
        "executive_summary": {"overall_risk_score": 0.0, "risk_band": "SECURE"},
        "sessions": [
            {
                "session_index": 1,
                "client": "10.0.0.1:123",
                "server": "10.0.0.2:25",
                "protocol": "SMTP",
                "starttls_state": "NOT_OBSERVED",
                "is_tls_implicit": False,
                "tls": None,
            }
        ],
        "findings": [],
        "drifts": [],
        "timeline": [],
        "limitations": [
            "TLS handshake was not observed for 1 plaintext or unupgraded session(s)."
        ],
    }

    html = generate_html_report(dummy_data)
    assert "TLS handshake was not observed" in html
    assert "Insufficient" in html or "Limitations" in html


@pytest.mark.anyio
async def test_security_path_traversal_prevention(client: AsyncClient):
    """Verify path traversal attempts are safely handled by routing."""
    resp = await client.get("/api/v1/reports/../../etc/passwd?format=json")
    assert resp.status_code in (404, 400)


@pytest.mark.anyio
async def test_openapi_schema_availability(client: AsyncClient):
    """Verify OpenAPI documentation endpoint returns valid v3.x schema."""
    resp = await client.get("/api/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    assert "openapi" in schema
    assert "paths" in schema
    assert "/api/v1/captures" in schema["paths"]
    assert "/api/v1/jobs" in schema["paths"]
    assert "/api/v1/reports/{job_id}" in schema["paths"]
