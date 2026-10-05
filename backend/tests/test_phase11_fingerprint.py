from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.analyzers.security_fingerprint import (
    build_security_fingerprint,
    compare_security_fingerprints,
)


def _fixture(**changes):
    handshake = SimpleNamespace(
        raw_client_hello_bytes=None,
        raw_server_hello_bytes=None,
        client_hello_frame=10,
        server_hello_frame=12,
        negotiated_tls_version="TLS 1.2",
        negotiated_cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange_group="secp256r1",
        is_forward_secrecy=True,
        offered_tls_versions="TLS 1.2",
        client_cipher_suites="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        sni_hostname="mail.example.test",
    )
    certificate = SimpleNamespace(
        is_server_cert=True,
        sha256_fingerprint="a" * 64,
        subject_dn="CN=mail.example.test",
        issuer_dn="CN=Example CA",
        san_domains='["mail.example.test"]',
        public_key_type="RSA",
        public_key_size_bits=2048,
        signature_algorithm="sha256WithRSAEncryption",
        is_valid_at_capture=True,
        is_self_signed=False,
    )
    session = SimpleNamespace(
        id="session-1",
        job_id="job-1",
        protocol="SMTP",
        is_tls_implicit=False,
        starttls_state="ACCEPTED",
        server_ip="192.0.2.10",
        server_port=25,
        hostname="mail.example.test",
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        risk_score=42.0,
        tls_handshake=handshake,
        starttls_details=SimpleNamespace(
            advertised_in_frame=4,
            command_in_frame=6,
            response_in_frame=7,
        ),
        certificates=[certificate],
        certificate_chain=SimpleNamespace(validation_status="VALIDATED"),
        findings=[],
    )
    job = SimpleNamespace(id="job-1", overall_risk_score=42.0, risk_band="MEDIUM")
    for key, value in changes.items():
        if key == "certificate_fingerprint":
            certificate.sha256_fingerprint = value
        elif key == "starttls_state":
            session.starttls_state = value
        elif key == "risk_score":
            session.risk_score = value
            job.overall_risk_score = value
        elif key == "tls":
            for name, attr in value.items():
                setattr(handshake, name, attr)
    return session, job


def _fingerprint(**changes):
    session, job = _fixture(**changes)
    return build_security_fingerprint(session, "capture-1", job)


def test_same_posture_has_deterministic_hash_despite_volatile_observation_data():
    first = _fingerprint()
    second_session, second_job = _fixture(risk_score=75.0)
    second_session.id = "session-other"
    second_session.start_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    second_job.id = "job-other"
    second = build_security_fingerprint(second_session, "capture-other", second_job)

    assert first["fingerprint_hash"] == second["fingerprint_hash"]
    assert first["evidence"]["capture_id"] != second["evidence"]["capture_id"]


@pytest.mark.parametrize(
    "change",
    [
        {"tls": {"negotiated_tls_version": "TLS 1.3"}},
        {"tls": {"negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256"}},
        {"certificate_fingerprint": "b" * 64},
        {"starttls_state": "REJECTED"},
    ],
)
def test_cryptographic_posture_changes_hash(change):
    baseline = _fingerprint()
    modified = _fingerprint(**change)

    assert baseline["fingerprint_hash"] != modified["fingerprint_hash"]
    assert compare_security_fingerprints(baseline, modified)["status"] == "CHANGED"


def test_unknown_optional_fields_are_null_and_not_fabricated():
    session, job = _fixture()
    session.tls_handshake.negotiated_tls_version = None
    session.certificates = []
    fingerprint = build_security_fingerprint(session, "capture-1", job)

    assert fingerprint["stable_profile"]["tls_version"] is None
    assert fingerprint["stable_profile"]["certificate"]["sha256_fingerprint"] is None
    assert "tls_version" not in fingerprint["hash_fields"]
    assert fingerprint["evidence"]["frames"]["certificate"] is None


def test_comparison_does_not_claim_change_when_value_is_only_observed_once():
    first = _fingerprint()
    second = _fingerprint()
    second["stable_profile"]["ja3"] = "observed-later"
    second["fingerprint_hash"] = "sha256:different"

    comparison = compare_security_fingerprints(first, second)

    assert comparison["status"] == "INDETERMINATE"
    assert comparison["differences"] == []
    assert "ja3" in comparison["not_comparable_fields"]


def test_comparison_reports_only_observed_field_differences():
    comparison = compare_security_fingerprints(_fingerprint(), _fingerprint(starttls_state="REJECTED"))

    assert comparison["status"] == "CHANGED"
    assert comparison["differences"] == [
        {"field": "starttls_state", "from": "ACCEPTED", "to": "REJECTED"}
    ]
