"""
Canonical Security Analysis Model Test Suite.
Exhaustively validates the 31 required risk & posture evolution scenarios:
- Determinism, boundedness (0-100), explainability, anti-double-counting.
- Unknown != Secure, explicit evidence confidence and observation completeness.
- Clean separation between Infrastructure Identity, Cryptographic Fingerprint, and Posture Evolution.
- Certificate rotation vs configuration regression.
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import List, Optional

import pytest

from app.models.certificate import Certificate, CertificateChain
from app.models.enums import Confidence, EvidenceStatus, FindingCategory, ProtocolType, RiskBand, Severity, StarttlsStatus
from app.models.finding import Evidence, Finding
from app.models.session import EmailSession, StarttlsState, TlsHandshake
from app.rules.evaluator import evaluate_rules_for_session
from app.rules.loader import load_rules_from_directory
from app.rules.risk_calculator import (
    EvidenceContext,
    RiskAssessment,
    RiskWeightsConfig,
    _risk_band_for_score,
    calculate_job_risk_score,
    calculate_session_risk_assessment,
    calculate_session_risk_score,
)
from app.analyzers.identity import construct_identity_key
from app.analyzers.security_fingerprint import build_security_fingerprint, compare_security_fingerprints
from app.analyzers.posture_evolution import PostureEvolutionType, classify_posture_evolution


def _make_dummy_finding(rule_id: str, severity: Severity, confidence: Confidence = Confidence.HIGH) -> Finding:
    f_id = str(uuid.uuid4())
    finding = Finding(
        id=f_id,
        job_id="job-test",
        session_id="sess-test",
        rule_id=rule_id,
        title=f"Finding for {rule_id}",
        category=FindingCategory.PROTOCOL_ANOMALY,
        severity=severity,
        confidence=confidence,
        status=EvidenceStatus.OBSERVED,
        description=f"Observed weakness for {rule_id}",
        remediation_recommendation="Remediation guidance",
    )
    ev = Evidence(
        finding_id=f_id,
        capture_id="cap-test",
        session_id="sess-test",
        frame_number=10,
        packet_timestamp=1700000000.0,
        protocol_layer="TLS",
        field_name="test_field",
        observed_value="test_value",
        evidence_status=EvidenceStatus.OBSERVED,
    )
    finding.evidence = [ev]
    return finding


def _create_session(
    protocol: ProtocolType = ProtocolType.SMTP,
    tls_version: Optional[str] = "TLS 1.3",
    cipher: Optional[str] = "TLS_AES_256_GCM_SHA384",
    stls_status: StarttlsStatus = StarttlsStatus.ACCEPTED,
    cert_valid: Optional[bool] = True,
    cert_sha256: str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900",
    cert_cn: str = "mail.example.org",
    fs: bool = True,
    kx_bits: int = 256,
    kx_group: str = "x25519",
) -> EmailSession:
    sess_id = str(uuid.uuid4())
    sess = EmailSession(
        id=sess_id,
        job_id="job-test",
        session_index=1,
        protocol=protocol,
        client_ip="192.168.1.10",
        server_ip="192.168.1.25",
        client_port=54321,
        server_port=25,
        starttls_state=stls_status,
        start_time=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 3, 1, 10, 0, 5, tzinfo=timezone.utc),
        packet_count=20,
        bytes_transferred=2500,
        hostname=cert_cn,
    )
    if tls_version:
        tls = TlsHandshake(
            id=str(uuid.uuid4()),
            session_id=sess_id,
            client_hello_frame=4,
            server_hello_frame=5,
            negotiated_tls_version=tls_version,
            negotiated_cipher_suite=cipher,
            key_exchange_group=kx_group,
            key_exchange_bits=kx_bits,
            is_forward_secrecy=fs,
            offered_tls_versions='["TLS 1.2", "TLS 1.3"]',
            handshake_status="COMPLETED",
        )
        sess.tls_handshake = tls
    else:
        sess.tls_handshake = None

    if cert_valid is not None:
        cert = Certificate(
            id=str(uuid.uuid4()),
            session_id=sess_id,
            subject_dn=f"CN={cert_cn}",
            issuer_dn="CN=GlobalCA",
            serial_number="12345678",
            sha256_fingerprint=cert_sha256,
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size_bits=2048,
            is_self_signed=False,
            is_valid_at_capture=cert_valid,
            not_before=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            san_domains='["' + cert_cn + '"]',
            certificate_index=0,
            is_server_cert=True,
        )
        sess.certificates = [cert]
        chain = CertificateChain(
            id=str(uuid.uuid4()),
            session_id=sess_id,
            chain_length=1,
            is_chain_complete=True,
            validation_status="VALIDATED",
        )
        sess.certificate_chain = chain
    else:
        sess.certificates = []
        sess.certificate_chain = None

    stls = StarttlsState(
        id=str(uuid.uuid4()),
        session_id=sess_id,
        observed_state=stls_status,
        advertised_in_frame=2,
        command_in_frame=3,
        response_in_frame=4,
        is_downgrade_detected=False,
    )
    sess.starttls_details = stls
    return sess


def _make_dummy_job() -> SimpleNamespace:
    return SimpleNamespace(id="job-test", overall_risk_score=20.0, risk_band="LOW")


# ─── 1. Completely secure TLS 1.3 ─────────────────────────────────────────────
def test_01_completely_secure_tls13():
    sess = _create_session(tls_version="TLS 1.3", cipher="TLS_AES_256_GCM_SHA384")
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assessment = calculate_session_risk_assessment(findings)
    assert assessment.score <= 15.0
    assert assessment.band in (RiskBand.SECURE, RiskBand.LOW)


# ─── 2. TLS 1.2 strong cipher ────────────────────────────────────────────────
def test_02_tls12_strong_cipher():
    sess = _create_session(tls_version="TLS 1.2", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assessment = calculate_session_risk_assessment(findings)
    assert assessment.score <= 20.0
    assert assessment.band in (RiskBand.SECURE, RiskBand.LOW)


# ─── 3. Deprecated TLS ───────────────────────────────────────────────────────
def test_03_deprecated_tls():
    sess = _create_session(tls_version="TLS 1.0", cipher="TLS_RSA_WITH_AES_128_CBC_SHA")
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assessment = calculate_session_risk_assessment(findings)
    assert any(f.rule_id == "CRYPT-001" for f in findings)
    assert assessment.score >= 60.0
    assert assessment.band in (RiskBand.HIGH, RiskBand.CRITICAL)


# ─── 4. RC4 / weak cipher ────────────────────────────────────────────────────
def test_04_weak_cipher_rc4():
    sess = _create_session(tls_version="TLS 1.2", cipher="TLS_RSA_WITH_RC4_128_SHA")
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assessment = calculate_session_risk_assessment(findings)
    assert any(f.rule_id == "CRYPT-005" for f in findings)
    assert assessment.score >= 80.0
    assert assessment.band == RiskBand.CRITICAL


# ─── 5. Expired certificate ──────────────────────────────────────────────────
def test_05_expired_certificate():
    sess = _create_session(cert_valid=False)
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assessment = calculate_session_risk_assessment(findings)
    assert any(f.rule_id == "CERT-001" for f in findings)
    assert assessment.score >= 40.0


# ─── 6. Invalid / self-signed certificate ─────────────────────────────────────
def test_06_self_signed_certificate():
    sess = _create_session()
    sess.certificates[0].is_self_signed = True
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assessment = calculate_session_risk_assessment(findings)
    assert any(f.rule_id in ("CERT-005", "CERT-006") for f in findings)
    assert assessment.score >= 10.0


# ─── 7. STARTTLS rejected ────────────────────────────────────────────────────
def test_07_starttls_rejected():
    sess = _create_session(stls_status=StarttlsStatus.REJECTED, tls_version=None)
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assert any(f.rule_id == "STLS-002" for f in findings)
    assessment = calculate_session_risk_assessment(findings)
    assert assessment.score >= 80.0
    assert assessment.band == RiskBand.CRITICAL


# ─── 8. STARTTLS unavailable ─────────────────────────────────────────────────
def test_08_starttls_unavailable():
    sess = _create_session(stls_status=StarttlsStatus.ADVERTISED, tls_version=None)
    # When advertised but client sends no STARTTLS, connection proceeds in cleartext -> STLS-001
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    assert any(f.rule_id == "STLS-001" for f in findings)
    assessment = calculate_session_risk_assessment(findings)
    assert assessment.score >= 60.0


# ─── 9. STARTTLS regression ──────────────────────────────────────────────────
def test_09_starttls_regression():
    fp_a = {"stable_profile": {"starttls_state": "ACCEPTED", "protocol": "SMTP"}, "fingerprint_hash": "hash-a"}
    fp_b = {"stable_profile": {"starttls_state": "REJECTED", "protocol": "SMTP"}, "fingerprint_hash": "hash-b"}
    evolution = classify_posture_evolution(fp_a, fp_b, differences=[{"field": "starttls_state", "from": "ACCEPTED", "to": "REJECTED"}])
    assert evolution["is_regression"] is True
    assert evolution["primary_category"] == "REGRESSION"


# ─── 10. Truncated TLS handshake ─────────────────────────────────────────────
def test_10_truncated_tls_handshake():
    context = EvidenceContext(
        observation_completeness=0.4,
        confidence="LOW",
        unknowns=["server_hello", "certificate"],
        limitations=["Handshake was truncated, observation incomplete"],
    )
    assessment = calculate_session_risk_assessment([], evidence_context=context)
    assert assessment.observation_completeness < 0.5
    assert assessment.confidence == "LOW"


# ─── 11. Missing certificate ─────────────────────────────────────────────────
def test_11_missing_certificate():
    sess = _create_session(cert_valid=None)
    rules = load_rules_from_directory()
    findings, _ = evaluate_rules_for_session(sess, "job-1", "cap-1", rules)
    cert_findings = [f for f in findings if f.rule_id.startswith("CERT-")]
    assert len(cert_findings) == 0


# ─── 12. Missing JA3 ─────────────────────────────────────────────────────────
def test_12_missing_ja3():
    sess = _create_session()
    job = _make_dummy_job()
    fp = build_security_fingerprint(sess, "cap-1", job)
    assert fp["stable_profile"]["ja3"] is None
    assert "fingerprint_hash" in fp
    assert fp["fingerprint_hash"].startswith("sha256:")


# ─── 13. Missing JA3S ────────────────────────────────────────────────────────
def test_13_missing_ja3s():
    sess = _create_session()
    job = _make_dummy_job()
    fp = build_security_fingerprint(sess, "cap-1", job)
    assert fp["stable_profile"]["ja3s"] is None
    assert "fingerprint_hash" in fp


# ─── 14. Certificate rotation ────────────────────────────────────────────────
def test_14_certificate_rotation():
    sess_a = _create_session(cert_sha256="1111111111111111111111111111111111111111111111111111111111111111")
    sess_b = _create_session(cert_sha256="2222222222222222222222222222222222222222222222222222222222222222")
    job = _make_dummy_job()

    # Infrastructure Identity must remain equal across certificate rotation
    key_a = construct_identity_key(sess_a.server_ip, sess_a.server_port, str(sess_a.protocol.value), sess_a.hostname)
    key_b = construct_identity_key(sess_b.server_ip, sess_b.server_port, str(sess_b.protocol.value), sess_b.hostname)
    assert key_a == key_b

    fp_a = build_security_fingerprint(sess_a, "cap-1", job)
    fp_b = build_security_fingerprint(sess_b, "cap-1", job)
    comp = compare_security_fingerprints(fp_a, fp_b)
    assert comp["posture_evolution"]["classification"] == PostureEvolutionType.CERTIFICATE_ROTATION.value
    assert comp["posture_evolution"]["is_regression"] is False


# ─── 15. TLS downgrade ───────────────────────────────────────────────────────
def test_15_tls_downgrade():
    fp_a = {"stable_profile": {"tls_version": "TLS 1.3"}, "fingerprint_hash": "hash-13"}
    fp_b = {"stable_profile": {"tls_version": "TLS 1.0"}, "fingerprint_hash": "hash-10"}
    comp = compare_security_fingerprints(fp_a, fp_b)
    assert comp["posture_evolution"]["classification"] == PostureEvolutionType.PROTOCOL_DOWNGRADE.value
    assert comp["posture_evolution"]["is_regression"] is True


# ─── 16. Cipher downgrade ────────────────────────────────────────────────────
def test_16_cipher_downgrade():
    fp_a = {"stable_profile": {"cipher_suite": "TLS_AES_256_GCM_SHA384"}, "fingerprint_hash": "hash-gcm"}
    fp_b = {"stable_profile": {"cipher_suite": "TLS_RSA_WITH_RC4_128_SHA"}, "fingerprint_hash": "hash-rc4"}
    comp = compare_security_fingerprints(fp_a, fp_b)
    assert comp["posture_evolution"]["classification"] == PostureEvolutionType.CIPHER_DOWNGRADE.value
    assert comp["posture_evolution"]["is_regression"] is True


# ─── 17. Repeated regression ─────────────────────────────────────────────────
def test_17_repeated_regression():
    scores = [85.0, 90.0, 88.0]
    job_risk = calculate_job_risk_score(scores)
    assert job_risk >= 85.0


# ─── 18. Multiple findings from one root cause ────────────────────────────────
def test_18_multiple_findings_from_one_root_cause():
    f1 = _make_dummy_finding("CRYPT-001", Severity.HIGH)
    f2 = _make_dummy_finding("CRYPT-002", Severity.HIGH)
    assessment_single = calculate_session_risk_assessment([f1])
    assessment_multi = calculate_session_risk_assessment([f1, f2])
    # The score should NOT double
    assert assessment_multi.score < assessment_single.score * 1.5
    assert len(assessment_multi.root_causes) == 1


# ─── 19. Duplicate findings ──────────────────────────────────────────────────
def test_19_duplicate_findings():
    f1 = _make_dummy_finding("CRYPT-005", Severity.CRITICAL)
    f2 = _make_dummy_finding("CRYPT-005", Severity.CRITICAL)
    assessment = calculate_session_risk_assessment([f1, f2])
    assert assessment.score <= 100.0
    assert len(assessment.root_causes) == 1


# ─── 20. Multiple sessions aggregation ───────────────────────────────────────
def test_20_multiple_sessions():
    scores = [100.0, 0.0, 0.0, 0.0]
    job_risk = calculate_job_risk_score(scores)
    # Expected: 0.7 * 100 + 0.3 * 25 = 70.0 + 7.5 = 77.5
    assert job_risk == 77.5


# ─── 21. Empty finding set ───────────────────────────────────────────────────
def test_21_empty_finding_set():
    assessment = calculate_session_risk_assessment([])
    assert assessment.score == 0.0
    assert assessment.band == RiskBand.SECURE
    assert assessment.root_causes == []


# ─── 22. Unknown evidence not secure ─────────────────────────────────────────
def test_22_unknown_evidence():
    context = EvidenceContext(
        observation_completeness=0.3,
        confidence="LOW",
        unknowns=["server_hello", "certificate"],
    )
    assessment = calculate_session_risk_assessment([], evidence_context=context)
    assert assessment.observation_completeness < 0.5
    assert assessment.confidence == "LOW"


# ─── 23. Partial evidence ────────────────────────────────────────────────────
def test_23_partial_evidence():
    context = EvidenceContext(
        observation_completeness=0.6,
        confidence="MEDIUM",
        unknowns=["certificate"],
    )
    assessment = calculate_session_risk_assessment([], evidence_context=context)
    assert assessment.observation_completeness == 0.6
    assert assessment.confidence == "MEDIUM"


# ─── 24. Complete evidence ───────────────────────────────────────────────────
def test_24_complete_evidence():
    context = EvidenceContext(
        observation_completeness=1.0,
        confidence="HIGH",
    )
    assessment = calculate_session_risk_assessment([], evidence_context=context)
    assert assessment.observation_completeness == 1.0
    assert assessment.confidence == "HIGH"


# ─── 25. Maximum risk bounded ────────────────────────────────────────────────
def test_25_maximum_risk():
    findings = [
        _make_dummy_finding("CRYPT-005", Severity.CRITICAL),
        _make_dummy_finding("STLS-002", Severity.CRITICAL),
        _make_dummy_finding("CRYPT-001", Severity.HIGH),
        _make_dummy_finding("CERT-001", Severity.HIGH),
    ]
    assessment = calculate_session_risk_assessment(findings)
    assert assessment.score == 100.0


# ─── 26. Minimum risk bounded ────────────────────────────────────────────────
def test_26_minimum_risk():
    assessment = calculate_session_risk_assessment([])
    assert assessment.score == 0.0


# ─── 27. Boundary thresholds ─────────────────────────────────────────────────
def test_27_boundary_thresholds():
    cfg = RiskWeightsConfig()
    score_sec, band_sec = calculate_session_risk_score([], config=cfg)
    assert band_sec == RiskBand.SECURE
    assert score_sec == 0.0

    assert _risk_band_for_score(0.0) == RiskBand.SECURE
    assert _risk_band_for_score(19.9) == RiskBand.SECURE
    assert _risk_band_for_score(20.0) == RiskBand.LOW
    assert _risk_band_for_score(39.9) == RiskBand.LOW
    assert _risk_band_for_score(40.0) == RiskBand.MEDIUM
    assert _risk_band_for_score(59.9) == RiskBand.MEDIUM
    assert _risk_band_for_score(60.0) == RiskBand.HIGH
    assert _risk_band_for_score(79.9) == RiskBand.HIGH
    assert _risk_band_for_score(80.0) == RiskBand.CRITICAL
    assert _risk_band_for_score(100.0) == RiskBand.CRITICAL


# ─── 28. Same PCAP processed twice (Determinism) ──────────────────────────────
def test_28_same_pcap_processed_twice():
    sess_1 = _create_session(tls_version="TLS 1.0", cipher="TLS_RSA_WITH_AES_128_CBC_SHA")
    sess_2 = _create_session(tls_version="TLS 1.0", cipher="TLS_RSA_WITH_AES_128_CBC_SHA")
    rules = load_rules_from_directory()
    f1, _ = evaluate_rules_for_session(sess_1, "job-1", "cap-1", rules)
    f2, _ = evaluate_rules_for_session(sess_2, "job-1", "cap-1", rules)
    a1 = calculate_session_risk_assessment(f1)
    a2 = calculate_session_risk_assessment(f2)
    assert a1.score == a2.score
    assert a1.band == a2.band
    assert len(a1.root_causes) == len(a2.root_causes)


# ─── 29. Different irrelevant metadata ────────────────────────────────────────
def test_29_different_irrelevant_metadata():
    sess_a = _create_session()
    sess_a.id = "custom-sess-a"
    sess_a.start_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    sess_b = _create_session()
    sess_b.id = "custom-sess-b"
    sess_b.start_time = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    job = _make_dummy_job()
    fp_a = build_security_fingerprint(sess_a, "cap-1", job)
    fp_b = build_security_fingerprint(sess_b, "cap-1", job)
    assert fp_a["fingerprint_hash"] == fp_b["fingerprint_hash"]


# ─── 30. Baseline improvement ─────────────────────────────────────────────────
def test_30_baseline_improvement():
    fp_a = {"stable_profile": {"tls_version": "TLS 1.2"}, "fingerprint_hash": "h-12"}
    fp_b = {"stable_profile": {"tls_version": "TLS 1.3"}, "fingerprint_hash": "h-13"}
    evolution = classify_posture_evolution(fp_a, fp_b, differences=[{"field": "tls_version", "from": "TLS 1.2", "to": "TLS 1.3"}])
    assert evolution["is_improvement"] is True
    assert evolution["is_regression"] is False
    assert evolution["primary_category"] == "IMPROVEMENT"


# ─── 31. Baseline regression ──────────────────────────────────────────────────
def test_31_baseline_regression():
    fp_a = {"stable_profile": {"tls_version": "TLS 1.3"}, "fingerprint_hash": "h-13"}
    fp_b = {"stable_profile": {"tls_version": "TLS 1.0"}, "fingerprint_hash": "h-10"}
    evolution = classify_posture_evolution(fp_a, fp_b, differences=[{"field": "tls_version", "from": "TLS 1.3", "to": "TLS 1.0"}])
    assert evolution["is_regression"] is True
    assert evolution["primary_category"] == "REGRESSION"

# Tests: assert risk score boundaries on synthetic test vectors
