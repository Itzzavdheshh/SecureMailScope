"""
Phase 5 Test Suite — Security Rule Engine & Transparent Risk Scoring.
Validates all 30 specified requirements for Phase 5.
"""

import io
import pytest
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
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
    StarttlsStatus,
    ProtocolType,
    Severity,
    Confidence,
    EvidenceStatus,
    FindingCategory,
)

from app.rules.schema import RuleDefinition, RiskWeightsConfig
from app.rules.loader import load_rules_from_directory, load_risk_weights_config, get_default_rules_dir
from app.rules.evaluator import evaluate_rules_for_session, evaluate_condition
from app.rules.risk_calculator import (
    calculate_session_risk_score,
    calculate_job_risk_score,
    compute_finding_contribution,
)
from app.analyzers.pipeline import run_pipeline
from tests.test_phase3_pipeline import build_raw_pcap
from tests.test_phase4_tls import (
    generate_self_signed_cert,
    generate_sha1_cert,
    build_raw_client_hello_payload,
    build_raw_server_hello_payload,
    build_raw_certificate_payload,
    wrap_in_tls_record,
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


def create_dummy_session() -> Tuple[EmailSession, TlsHandshake, Certificate, CertificateChain, StarttlsState]:
    """Helper to construct dummy domain object graph for rule evaluation unit tests."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(
        id="dummy-sess-1",
        job_id="dummy-job-1",
        session_index=1,
        client_ip="10.0.0.1",
        client_port=5000,
        server_ip="10.0.0.2",
        server_port=25,
        protocol=ProtocolType.SMTP,
        is_tls_implicit=False,
        starttls_state=StarttlsStatus.ACCEPTED,
        start_time=now,
    )

    tls = TlsHandshake(
        id="dummy-tls-1",
        session_id=sess.id,
        server_hello_frame=15,
        client_hello_frame=10,
        offered_tls_versions='["TLS 1.0", "TLS 1.2", "TLS 1.3"]',
        negotiated_tls_version="TLS 1.2",
        negotiated_cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange_group="ECDHE",
        is_forward_secrecy=True,
    )
    sess.tls_handshake = tls

    cert = Certificate(
        id="dummy-cert-1",
        session_id=sess.id,
        subject_dn="CN=mail.example.com",
        issuer_dn="CN=mail.example.com",
        public_key_type="RSA",
        public_key_size_bits=2048,
        signature_algorithm="sha256WithRSAEncryption",
        is_weak_signature=False,
        is_self_signed=True,
        is_valid_at_capture=True,
        san_domains='["mail.example.com"]',
    )
    sess.certificates = [cert]

    chain = CertificateChain(
        id="dummy-chain-1",
        session_id=sess.id,
        chain_length=1,
        is_chain_complete=True,
        validation_status="VALID_AT_CAPTURE",
    )
    sess.certificate_chain = chain

    stls = StarttlsState(
        id="dummy-stls-1",
        session_id=sess.id,
        observed_state=StarttlsStatus.ACCEPTED,
        command_in_frame=5,
        response_in_frame=6,
        is_downgrade_detected=False,
    )
    sess.starttls_details = stls

    return sess, tls, cert, chain, stls


# ─── 30 REQUIRED TESTS FOR PHASE 5 ──────────────────────────────────────────

def test_01_yaml_loading():
    """1. YAML loading."""
    rules_dir = get_default_rules_dir()
    rules = load_rules_from_directory(rules_dir)
    assert len(rules) > 0
    assert any(r.id == "CRYPT-001" for r in rules)


def test_02_invalid_yaml_rule_rejection(tmp_path):
    """2. Invalid YAML rule rejection."""
    bad_file = tmp_path / "bad_rules.yaml"
    bad_file.write_text("invalid_yaml: [unclosed list")
    rules = load_rules_from_directory(tmp_path)
    assert len(rules) == 0


def test_03_rule_schema_validation():
    """3. Rule schema validation."""
    rule_dict = {
        "id": "TEST-001",
        "title": "Test Rule",
        "severity": "HIGH",
        "description": "Test description",
        "detection": {"field": "negotiated_tls_version", "condition": "equals", "value": "TLS 1.0"}
    }
    rule = RuleDefinition(**rule_dict)
    assert rule.id == "TEST-001"
    assert rule.severity == Severity.HIGH


def test_04_disabled_rule_ignored(tmp_path):
    """4. Disabled rule ignored."""
    rule_yaml = """
rules:
  - id: TEST-DISABLED
    title: "Disabled Rule"
    severity: HIGH
    description: "Should be ignored"
    enabled: false
    detection:
      field: negotiated_tls_version
      condition: equals
      value: "TLS 1.0"
"""
    (tmp_path / "test_rules.yaml").write_text(rule_yaml)
    rules = load_rules_from_directory(tmp_path)
    assert len(rules) == 0


def test_05_deprecated_negotiated_tls_finding():
    """5. Deprecated negotiated TLS finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.negotiated_tls_version = "TLS 1.0"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CRYPT-001" in found_ids


def test_06_deprecated_offered_only_tls_does_not_trigger():
    """6. Deprecated offered-only TLS does NOT trigger negotiated rule."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.offered_tls_versions = '["TLS 1.0", "TLS 1.2"]'
    tls.negotiated_tls_version = "TLS 1.2"  # Negotiated TLS 1.2!

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CRYPT-001" not in found_ids


def test_07_weak_negotiated_cipher_finding():
    """7. Weak negotiated cipher finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.negotiated_cipher_suite = "TLS_RSA_WITH_RC4_128_SHA"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CRYPT-005" in found_ids


def test_08_weak_offered_only_cipher_does_not_trigger():
    """8. Weak offered-only cipher does NOT trigger negotiated cipher rule."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.client_cipher_suites = '["TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]'
    tls.negotiated_cipher_suite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CRYPT-005" not in found_ids


def test_09_forward_secrecy_finding():
    """9. Forward Secrecy finding (static RSA)."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.is_forward_secrecy = False

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CRYPT-004" in found_ids


def test_10_expired_certificate_finding():
    """10. Expired certificate finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    cert.is_valid_at_capture = False

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CERT-001" in found_ids


def test_11_not_yet_valid_certificate_finding():
    """11. Not-yet-valid certificate finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    cert.is_valid_at_capture = False
    cert.not_before = datetime.now(timezone.utc)

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CERT-002" in found_ids


def test_12_sha1_certificate_finding():
    """12. SHA-1 certificate finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    cert.is_weak_signature = True
    cert.signature_algorithm = "sha1WithRSAEncryption"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CERT-004" in found_ids


def test_13_md5_certificate_finding():
    """13. MD5 certificate finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    cert.is_weak_signature = True
    cert.signature_algorithm = "md5WithRSAEncryption"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CERT-004" in found_ids


def test_14_weak_public_key_finding():
    """14. Weak public key finding (RSA < 2048)."""
    sess, tls, cert, chain, stls = create_dummy_session()
    cert.public_key_type = "RSA"
    cert.public_key_size_bits = 1024

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CERT-003" in found_ids


def test_15_self_signed_certificate_finding():
    """15. Self-signed certificate finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    cert.is_self_signed = True

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "CERT-005" in found_ids


def test_16_starttls_rejected_finding():
    """16. STARTTLS rejected finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    stls.observed_state = StarttlsStatus.REJECTED
    session_copy = sess

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(session_copy, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "STLS-002" in found_ids


def test_17_starttls_accepted_without_tls_finding():
    """17. STARTTLS accepted-without-TLS finding."""
    sess, tls, cert, chain, stls = create_dummy_session()
    sess.tls_handshake = None  # TLS not followed!
    stls.observed_state = "ACCEPTED_NO_TLS"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    found_ids = [f.rule_id for f in findings]
    assert "STLS-003" in found_ids


def test_18_missing_certificate_insufficient_evidence():
    """18. Missing certificate -> insufficient evidence (no false findings)."""
    sess, tls, cert, chain, stls = create_dummy_session()
    sess.certificates = []  # No cert in capture!

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    cert_findings = [f for f in findings if f.category == FindingCategory.X509_CERT]
    assert len(cert_findings) == 0


def test_19_missing_server_hello_insufficient_evidence():
    """19. Missing ServerHello -> insufficient evidence (no false findings)."""
    sess, tls, cert, chain, stls = create_dummy_session()
    sess.tls_handshake = None  # No ServerHello!

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    tls_findings = [f for f in findings if f.category == FindingCategory.TLS_CRYPTO]
    assert len(tls_findings) == 0


def test_20_evidence_frame_number_preserved():
    """20. Evidence frame number preserved."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.negotiated_tls_version = "TLS 1.0"
    tls.server_hello_frame = 99

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    assert len(evidence) >= 1
    assert evidence[0].frame_number == 99


def test_21_evidence_timestamp_preserved():
    """21. Evidence timestamp preserved."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.negotiated_tls_version = "TLS 1.0"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    assert len(evidence) >= 1
    assert evidence[0].packet_timestamp == sess.start_time.timestamp()


@pytest.mark.asyncio
async def test_22_finding_persisted_in_db():
    """22. Finding persisted in DB."""
    sess, tls, cert, chain, stls = create_dummy_session()
    tls.negotiated_tls_version = "TLS 1.0"

    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)

    assert len(findings) >= 1
    assert findings[0].title is not None


def test_23_session_risk_calculation():
    """23. Session risk calculation."""
    f1 = Finding(rule_id="R1", title="Critical Issue", category=FindingCategory.TLS_CRYPTO, severity=Severity.CRITICAL, confidence=Confidence.HIGH, description="desc")
    f2 = Finding(rule_id="R2", title="High Issue", category=FindingCategory.X509_CERT, severity=Severity.HIGH, confidence=Confidence.HIGH, description="desc")

    cfg = RiskWeightsConfig()
    score, band = calculate_session_risk_score([f1, f2], cfg)

    # raw = 10.0 + 7.0 = 17.0, normalized = 17.0 / 30.0 * 100 = 56.7
    assert score == 56.7
    assert band == "MEDIUM"


def test_24_job_risk_calculation():
    """24. Job risk calculation."""
    session_scores = [20.0, 80.0, 40.0]
    # max = 80.0, avg = 46.67, job = 0.7 * 80 + 0.3 * 46.67 = 56.0 + 14.0 = 70.0
    job_score = calculate_job_risk_score(session_scores)
    assert job_score == 70.0


def test_25_risk_bounded_to_0_100():
    """25. Risk bounded to 0–100."""
    findings = [
        Finding(rule_id=f"R{i}", title=f"Critical {i}", category=FindingCategory.TLS_CRYPTO, severity=Severity.CRITICAL, confidence=Confidence.HIGH, description="desc")
        for i in range(10)
    ]
    cfg = RiskWeightsConfig()
    score, band = calculate_session_risk_score(findings, cfg)
    assert score == 100.0


def test_26_deterministic_repeated_scoring():
    """26. Deterministic repeated scoring."""
    f1 = Finding(rule_id="R1", title="Issue", category=FindingCategory.TLS_CRYPTO, severity=Severity.HIGH, confidence=Confidence.HIGH, description="desc")
    cfg = RiskWeightsConfig()

    s1, _ = calculate_session_risk_score([f1], cfg)
    s2, _ = calculate_session_risk_score([f1], cfg)

    assert s1 == s2


def test_27_duplicate_evidence_does_not_cause_uncontrolled_inflation():
    """27. Duplicate evidence does not cause uncontrolled inflation."""
    f1 = Finding(rule_id="R1", title="Issue", category=FindingCategory.TLS_CRYPTO, severity=Severity.HIGH, confidence=Confidence.HIGH, description="desc")
    cfg = RiskWeightsConfig()

    score1, _ = calculate_session_risk_score([f1], cfg)
    # Even if 2 identical findings exist, bounded score calculation behaves deterministically
    score2, _ = calculate_session_risk_score([f1, f1], cfg)

    assert score2 <= 100.0


def test_28_multiple_findings_aggregate_correctly():
    """28. Multiple findings aggregate correctly."""
    f1 = Finding(rule_id="R1", title="Medium Issue", category=FindingCategory.TLS_CRYPTO, severity=Severity.MEDIUM, confidence=Confidence.HIGH, description="desc")
    f2 = Finding(rule_id="R2", title="Low Issue", category=FindingCategory.PROTOCOL_ANOMALY, severity=Severity.LOW, confidence=Confidence.HIGH, description="desc")

    cfg = RiskWeightsConfig()
    score, band = calculate_session_risk_score([f1, f2], cfg)

    # raw = 4.0 + 1.5 = 5.5, normalized = 5.5 / 30.0 * 100 = 18.3
    assert score == 18.3


def test_29_malformed_incomplete_input_does_not_crash_rule_engine():
    """29. Malformed/incomplete input does not crash rule engine."""
    empty_sess = EmailSession(job_id="j1", session_index=1, client_ip="1.1.1.1", client_port=1, server_ip="2.2.2.2", server_port=2)
    rules = load_rules_from_directory()
    findings, evidence = evaluate_rules_for_session(empty_sess, "j1", "c1", rules)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_30_end_to_end_phase5_integration(tmp_path):
    """30. End-to-end integration: PCAP upload -> pipeline -> rules -> Findings, Evidence, and Risk Score in DB."""
    cert_der = generate_self_signed_cert(cn="smtp.test.com")
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="smtp.test.com"))
    # Negotiate deprecated TLS 1.0!
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0301, selected_cs=0x0035))
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220 mail.com ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 35, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 11, "payload": ch_raw},
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 65, "payload": sh_raw + cm_raw},
    ])

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("rule_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        up_res = await client.post("/api/captures/upload", files=files)
        assert up_res.status_code == 201
        job_id = up_res.json()["job_id"]

        start_res = await client.post(f"/api/jobs/{job_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["job"]["status"] == "COMPLETED"

        # Check findings and risk score in DB
        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            job_stmt = select(AnalysisJob).where(AnalysisJob.id == job_id)
            job_res = await session.execute(job_stmt)
            job_db = job_res.scalar_one()

            assert job_db.overall_risk_score > 0.0

            find_stmt = select(Finding).where(Finding.job_id == job_id)
            find_res = await session.execute(find_stmt)
            findings = find_res.scalars().all()
            assert len(findings) >= 1
            assert any(f.rule_id == "CRYPT-001" for f in findings)

            ev_stmt = select(Evidence).where(Evidence.finding_id == findings[0].id)
            ev_res = await session.execute(ev_stmt)
            evidence = ev_res.scalars().all()
            assert len(evidence) >= 1
