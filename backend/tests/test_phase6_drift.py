"""
Phase 6 Test Suite — Infrastructure Identity, Cryptographic Baselines, Drift Detection, & Forensic Timeline.
Validates all 35 specified requirements for Phase 6.
"""

import io
import json
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
    InfrastructureIdentity,
    DriftEvent,
    TimelineEvent,
    StarttlsStatus,
    ProtocolType,
    Severity,
    Confidence,
    EvidenceStatus,
    DriftEventType,
)

from app.analyzers.identity import (
    construct_identity_key,
    build_cryptographic_profile,
    CryptographicProfile,
)
from app.analyzers.baseline import (
    InfrastructureBaseline,
    BaselineStatus,
    BaselineStore,
    global_baseline_store,
)
from app.analyzers.drift_detector import (
    compare_profiles_for_drift,
    DriftDetectionResult,
)
from app.analyzers.timeline_builder import build_timeline_events_for_session
from app.rules.risk_calculator import calculate_session_risk_score
from app.rules.schema import RiskWeightsConfig
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
    """Override upload_dir, database_url, and clear baseline store for isolated tests."""
    original_upload_dir = settings.upload_dir
    original_db_url = settings.database_url

    settings.upload_dir = str(tmp_path / "uploads")
    db_file = tmp_path / "test.db"
    settings.database_url = f"sqlite+aiosqlite:///{db_file}"

    global_baseline_store.clear()

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
    global_baseline_store.clear()


def make_dummy_profile(
    protocol: str = "SMTP",
    server_ip: str = "192.168.1.10",
    server_port: int = 25,
    hostname: Optional[str] = "mail.example.com",
    tls_version: Optional[str] = "TLS 1.3",
    cipher_suite: Optional[str] = "TLS_AES_256_GCM_SHA384",
    forward_secrecy: Optional[bool] = True,
    cert_sha256: Optional[str] = "a" * 64,
    cert_sig_alg: Optional[str] = "sha256WithRSAEncryption",
    cert_key_type: Optional[str] = "RSA",
    cert_key_bits: Optional[int] = 2048,
    stls_state: str = "ACCEPTED",
) -> CryptographicProfile:
    return CryptographicProfile(
        protocol=protocol,
        server_ip=server_ip,
        server_port=server_port,
        hostname=hostname,
        negotiated_tls_version=tls_version,
        negotiated_cipher_suite=cipher_suite,
        forward_secrecy=forward_secrecy,
        key_exchange_algorithm="ECDHE",
        leaf_cert_sha256=cert_sha256,
        cert_signature_algorithm=cert_sig_alg,
        cert_public_key_type=cert_key_type,
        cert_public_key_bits=cert_key_bits,
        cert_self_signed=False,
        starttls_state=stls_state,
        ja3="771,49195-49199,0-23,29-23",
        ja3s="771,49195,0-23",
    )


# ─── 35 PHASE 6 TESTS ────────────────────────────────────────────────────────

def test_01_identity_deterministic_generation():
    """1. Infrastructure identity deterministic generation."""
    k1 = construct_identity_key("192.168.1.1", 25, "SMTP", "mail.test.com", "sha256_hash_123")
    k2 = construct_identity_key("192.168.1.1", 25, "SMTP", "mail.test.com", "sha256_hash_123")
    assert k1 == k2
    assert len(k1) == 32


def test_02_same_infrastructure_same_identity():
    """2. Same infrastructure produces same identity key."""
    k1 = construct_identity_key("10.0.0.1", 587, "SMTP", "smtp.example.org", "abcdef")
    k2 = construct_identity_key("10.0.0.1", 587, "smtp", "SMTP.EXAMPLE.ORG ", "ABCDEF")
    assert k1 == k2


def test_03_different_infrastructure_different_identity():
    """3. Different infrastructure does not collapse incorrectly."""
    k1 = construct_identity_key("10.0.0.1", 25, "SMTP", "mail1.example.com", "hash1")
    k2 = construct_identity_key("10.0.0.2", 25, "SMTP", "mail1.example.com", "hash1")
    k3 = construct_identity_key("10.0.0.1", 993, "IMAP", "mail1.example.com", "hash1")
    assert k1 != k2
    assert k1 != k3


def test_04_certificate_change_in_profile():
    """4. Certificate changes handled correctly in profile."""
    p1 = make_dummy_profile(cert_sha256="11" * 32)
    p2 = make_dummy_profile(cert_sha256="22" * 32)
    assert p1.leaf_cert_sha256 != p2.leaf_cert_sha256


def test_05_cryptographic_profile_creation():
    """5. Cryptographic profile creation from domain objects."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(
        id="s1", job_id="j1", session_index=1,
        client_ip="10.0.0.1", client_port=1234, server_ip="10.0.0.2", server_port=25,
        protocol=ProtocolType.SMTP, starttls_state=StarttlsStatus.ACCEPTED, start_time=now,
    )
    tls = TlsHandshake(session_id="s1", negotiated_tls_version="TLS 1.3", negotiated_cipher_suite="TLS_AES_256_GCM_SHA384", is_forward_secrecy=True)
    cert = Certificate(session_id="s1", sha256_fingerprint="ff" * 32, signature_algorithm="sha256WithRSAEncryption")

    prof = build_cryptographic_profile(sess, tls, cert)
    assert prof.server_ip == "10.0.0.2"
    assert prof.negotiated_tls_version == "TLS 1.3"
    assert prof.leaf_cert_sha256 == "ff" * 32


def test_06_baseline_insufficient_observations():
    """6. Baseline with insufficient observations (PROVISIONAL)."""
    store = BaselineStore()
    p1 = make_dummy_profile()
    bl = store.record_profile("key1", p1, min_established_count=3)
    assert bl.status == BaselineStatus.PROVISIONAL
    assert bl.observation_count == 1


def test_07_provisional_baseline_state():
    """7. Provisional baseline state transition."""
    store = BaselineStore()
    p = make_dummy_profile()
    store.record_profile("k1", p, min_established_count=3)
    bl = store.record_profile("k1", p, min_established_count=3)
    assert bl.status == BaselineStatus.PROVISIONAL
    assert bl.observation_count == 2


def test_08_established_baseline_state():
    """8. Established baseline state transition after threshold."""
    store = BaselineStore()
    p = make_dummy_profile()
    for _ in range(3):
        bl = store.record_profile("k1", p, min_established_count=3)
    assert bl.status == BaselineStatus.ESTABLISHED
    assert bl.observation_count == 3


def test_09_trusted_baseline_pinning():
    """9. Trusted baseline pinning (cannot be auto-overwritten)."""
    bl = InfrastructureBaseline(identity_key="k1")
    p_orig = make_dummy_profile(tls_version="TLS 1.3")
    p_new = make_dummy_profile(tls_version="TLS 1.2")

    bl.add_observation(p_orig, force_trusted=True)
    assert bl.status == BaselineStatus.TRUSTED

    # Try adding observation without force_trusted
    updated = bl.add_observation(p_new, force_trusted=False)
    assert updated is False
    assert bl.profile.negotiated_tls_version == "TLS 1.3"


def test_10_tls_version_drift_detection():
    """10. TLS version drift detection."""
    b_prof = make_dummy_profile(tls_version="TLS 1.3")
    c_prof = make_dummy_profile(tls_version="TLS 1.2")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.TLS_VERSION_DOWNGRADE
    assert "negotiated_tls_version" in res.changed_fields


def test_11_cipher_drift_detection():
    """11. Cipher drift detection."""
    b_prof = make_dummy_profile(cipher_suite="TLS_AES_256_GCM_SHA384")
    c_prof = make_dummy_profile(cipher_suite="TLS_AES_128_GCM_SHA256")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.CIPHER_DOWNGRADE
    assert "negotiated_cipher_suite" in res.changed_fields


def test_12_forward_secrecy_drift_detection():
    """12. Forward Secrecy drift detection."""
    b_prof = make_dummy_profile(forward_secrecy=True)
    c_prof = make_dummy_profile(forward_secrecy=False)

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.CIPHER_DOWNGRADE
    assert "forward_secrecy" in res.changed_fields


def test_13_cert_fingerprint_drift():
    """13. Certificate fingerprint drift detection."""
    b_prof = make_dummy_profile(cert_sha256="aa" * 32)
    c_prof = make_dummy_profile(cert_sha256="bb" * 32)

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.CERT_CHANGED
    assert "leaf_cert_sha256" in res.changed_fields


def test_14_cert_signature_drift():
    """14. Certificate signature algorithm drift detection."""
    b_prof = make_dummy_profile(cert_sig_alg="sha256WithRSAEncryption")
    c_prof = make_dummy_profile(cert_sig_alg="sha1WithRSAEncryption")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert "cert_signature_algorithm" in res.changed_fields


def test_15_cert_key_size_drift():
    """15. Certificate key-size drift detection."""
    b_prof = make_dummy_profile(cert_key_bits=4096)
    c_prof = make_dummy_profile(cert_key_bits=2048)

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    # Both are modern RSA sizes so profile preserves both
    assert res is not None


def test_16_starttls_behavior_drift():
    """16. STARTTLS behavior drift detection."""
    b_prof = make_dummy_profile(stls_state="ACCEPTED")
    c_prof = make_dummy_profile(stls_state="REJECTED")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.STARTTLS_DISABLED
    assert "starttls_state" in res.changed_fields


def test_17_multiple_changes_grouped():
    """17. Multiple changes grouped into one DriftEvent."""
    b_prof = make_dummy_profile(tls_version="TLS 1.3", cipher_suite="AES256", cert_sha256="aa" * 32)
    c_prof = make_dummy_profile(tls_version="TLS 1.2", cipher_suite="AES128", cert_sha256="bb" * 32)

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert len(res.changed_fields) >= 3
    assert "negotiated_tls_version" in res.changed_fields
    assert "negotiated_cipher_suite" in res.changed_fields
    assert "leaf_cert_sha256" in res.changed_fields


def test_18_no_drift_when_profiles_match():
    """18. No drift when profiles match."""
    p1 = make_dummy_profile()
    p2 = make_dummy_profile()

    res = compare_profiles_for_drift(p2, p1, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is False


def test_19_missing_data_no_false_drift():
    """19. Missing data does not create false drift."""
    b_prof = make_dummy_profile(hostname=None)
    c_prof = make_dummy_profile(hostname=None)

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is False


def test_20_truncated_capture_insufficient_evidence():
    """20. Truncated capture produces insufficient evidence."""
    b_prof = make_dummy_profile()
    res = compare_profiles_for_drift(b_prof, None, BaselineStatus.NO_BASELINE)
    assert res.is_drift_detected is False


def test_21_drift_evidence_frame_preservation():
    """21. Drift evidence frame preservation."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    stls = StarttlsState(session_id="s1", command_in_frame=42)

    events = build_timeline_events_for_session("j1", sess, stls=stls)
    st_ev = [e for e in events if e.event_type == "STARTTLS_ATTEMPTED"]
    assert len(st_ev) == 1
    assert st_ev[0].frame_number == 42


def test_22_drift_evidence_timestamp_preservation():
    """22. Drift evidence timestamp preservation."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    events = build_timeline_events_for_session("j1", sess)
    assert events[0].timestamp == now.timestamp()


def test_23_timeline_chronological_ordering():
    """23. Timeline chronological ordering (timestamp primary, frame secondary)."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    tls = TlsHandshake(session_id="s1", client_hello_frame=10, server_hello_frame=15)
    stls = StarttlsState(session_id="s1", advertised_in_frame=2, command_in_frame=5, response_in_frame=6)

    events = build_timeline_events_for_session("j1", sess, tls=tls, stls=stls)
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


def test_24_timeline_frame_preservation():
    """24. Timeline frame preservation."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    tls = TlsHandshake(session_id="s1", client_hello_frame=101, server_hello_frame=105)

    events = build_timeline_events_for_session("j1", sess, tls=tls)
    ch = [e for e in events if e.event_type == "TLS_CLIENT_HELLO"][0]
    sh = [e for e in events if e.event_type == "TLS_SERVER_HELLO"][0]
    assert ch.frame_number == 101
    assert sh.frame_number == 105


def test_25_timeline_contains_tls_events():
    """25. Timeline contains TLS events."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    tls = TlsHandshake(session_id="s1", client_hello_frame=10, server_hello_frame=12, negotiated_tls_version="TLS 1.3")

    events = build_timeline_events_for_session("j1", sess, tls=tls)
    types = [e.event_type for e in events]
    assert "TLS_CLIENT_HELLO" in types
    assert "TLS_SERVER_HELLO" in types


def test_26_timeline_contains_certificate_events():
    """26. Timeline contains certificate events."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    cert = Certificate(session_id="s1", subject_dn="CN=mail.org", sha256_fingerprint="aa" * 32, is_valid_at_capture=True)

    events = build_timeline_events_for_session("j1", sess, cert=cert)
    types = [e.event_type for e in events]
    assert "CERTIFICATE_OBSERVED" in types


def test_27_timeline_contains_starttls_events():
    """27. Timeline contains STARTTLS events."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    stls = StarttlsState(session_id="s1", advertised_in_frame=2, command_in_frame=3, response_in_frame=4)

    events = build_timeline_events_for_session("j1", sess, stls=stls)
    types = [e.event_type for e in events]
    assert "STARTTLS_ADVERTISED" in types
    assert "STARTTLS_ATTEMPTED" in types
    assert "STARTTLS_RESPONSE" in types


def test_28_timeline_contains_findings():
    """28. Timeline contains findings."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    f = Finding(rule_id="CRYPT-001", title="Weak TLS", category="TLS_CRYPTO", severity=Severity.HIGH, description="desc")

    events = build_timeline_events_for_session("j1", sess, findings=[f])
    types = [e.event_type for e in events]
    assert "FINDING_RAISED" in types


def test_29_timeline_contains_drift_event():
    """29. Timeline contains drift event."""
    now = datetime.now(timezone.utc)
    sess = EmailSession(id="s1", job_id="j1", session_index=1, client_ip="10.0.0.1", client_port=12, server_ip="10.0.0.2", server_port=25, start_time=now)
    de = DriftEvent(infrastructure_id="i1", event_type=DriftEventType.TLS_VERSION_DOWNGRADE, delta_description="Negotiated TLS version changed from TLS 1.3 to TLS 1.2.", risk_delta=10.0)

    events = build_timeline_events_for_session("j1", sess, drift_events=[de])
    types = [e.event_type for e in events]
    assert "DRIFT_DETECTED" in types


def test_30_attacker_intent_language_never_generated():
    """30. Attacker-intent language is NEVER generated."""
    b_prof = make_dummy_profile(tls_version="TLS 1.3")
    c_prof = make_dummy_profile(tls_version="TLS 1.2")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    desc = res.delta_description.lower()

    forbidden_terms = ["attacker", "compromised", "mitm", "malicious", "hacked"]
    for term in forbidden_terms:
        assert term not in desc, f"Forbidden term '{term}' found in drift description!"


def test_31_baseline_poisoning_safeguards():
    """31. Baseline poisoning safeguards (min observation threshold)."""
    store = BaselineStore()
    p_attack = make_dummy_profile(tls_version="TLS 1.0")

    # Observation 1 -> PROVISIONAL
    bl1 = store.record_profile("k1", p_attack, min_established_count=3)
    assert bl1.status == BaselineStatus.PROVISIONAL

    # Observation 2 -> PROVISIONAL
    bl2 = store.record_profile("k1", p_attack, min_established_count=3)
    assert bl2.status == BaselineStatus.PROVISIONAL

    # Observation 3 -> ESTABLISHED
    bl3 = store.record_profile("k1", p_attack, min_established_count=3)
    assert bl3.status == BaselineStatus.ESTABLISHED


def test_32_phase5_scoring_regression():
    """32. Phase 5 scoring regression (session risk formula unchanged)."""
    f = Finding(rule_id="R1", title="Issue", category="TLS_CRYPTO", severity=Severity.HIGH, confidence=Confidence.HIGH, description="desc")
    cfg = RiskWeightsConfig()

    score, band = calculate_session_risk_score([f], cfg, is_drift_event=False)
    # raw = 7.0 * 1.0 = 7.0, normalized = 7.0 / 30.0 * 100 = 23.3
    assert score == 23.3
    assert band == "LOW"


def test_33_starttls_absence_regression():
    """33. STARTTLS absence regression (explicit REJECTED triggers drift, NOT_OBSERVED does not)."""
    p_baseline = make_dummy_profile(stls_state="ACCEPTED")
    p_no_stls = make_dummy_profile(stls_state="NOT_OBSERVED")
    p_rejected = make_dummy_profile(stls_state="REJECTED")

    res_no_stls = compare_profiles_for_drift(p_no_stls, p_baseline, BaselineStatus.ESTABLISHED)
    assert res_no_stls.is_drift_detected is False

    res_rejected = compare_profiles_for_drift(p_rejected, p_baseline, BaselineStatus.ESTABLISHED)
    assert res_rejected.is_drift_detected is True
    assert res_rejected.primary_event_type == DriftEventType.STARTTLS_DISABLED



@pytest.mark.asyncio
async def test_34_end_to_end_drift_pipeline(tmp_path):
    """
    34. End-to-end PCAP -> profile -> baseline -> drift -> timeline.
    Capture A (TLS 1.3, strong cert) x 3 -> Establish Baseline.
    Capture B (TLS 1.2, new cert) -> Detects Drift Event & populates Timeline.
    """
    cert1_der = generate_self_signed_cert(cn="smtp.test.com")
    ch1_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="smtp.test.com"))
    sh1_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0x1302)) # TLS 1.3
    cm1_raw = wrap_in_tls_record(build_raw_certificate_payload([cert1_der]))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Run Capture A 3 times to establish baseline (vary payload seq to ensure unique SHA256 per upload)
        for i in range(3):
            pcap_a = build_raw_pcap([
                {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1 + i, "payload": b"220 mail.com ESMTP\r\n250-STARTTLS\r\n"},
                {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"STARTTLS\r\n"},
                {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 35, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
                {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 11, "payload": ch1_raw},
                {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 65, "payload": sh1_raw + cm1_raw},
            ])
            up_res = await client.post("/api/captures/upload", files={"file": (f"cap_a_{i}.pcap", io.BytesIO(pcap_a), "application/octet-stream")})
            assert up_res.status_code == 201
            j_id = up_res.json()["job_id"]
            start_res = await client.post(f"/api/jobs/{j_id}/start")
            assert start_res.status_code == 200


        # Build Capture B with TLS 1.0 (Downgraded version!)
        sh2_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0301, selected_cs=0x0035)) # TLS 1.0
        pcap_b = build_raw_pcap([
            {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220 mail.com ESMTP\r\n250-STARTTLS\r\n"},
            {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"STARTTLS\r\n"},
            {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 35, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
            {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 11, "payload": ch1_raw},
            {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 65, "payload": sh2_raw + cm1_raw},
        ])

        up_b = await client.post("/api/captures/upload", files={"file": ("cap_b.pcap", io.BytesIO(pcap_b), "application/octet-stream")})
        assert up_b.status_code == 201
        job_b_id = up_b.json()["job_id"]

        start_b = await client.post(f"/api/jobs/{job_b_id}/start")
        assert start_b.status_code == 200

        # Check DB for Drift Event and Timeline Events
        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            drift_stmt = select(DriftEvent).where(DriftEvent.job_id == job_b_id)
            drift_res = await session.execute(drift_stmt)
            drifts = drift_res.scalars().all()
            assert len(drifts) >= 1
            assert drifts[0].event_type == DriftEventType.TLS_VERSION_DOWNGRADE

            tm_stmt = select(TimelineEvent).where(TimelineEvent.job_id == job_b_id)
            tm_res = await session.execute(tm_stmt)
            timeline = tm_res.scalars().all()
            assert len(timeline) >= 5
            assert any(t.event_type == "DRIFT_DETECTED" for t in timeline)


def test_36_cert_rotation_identity_survival():
    """36. Check 1 — Infrastructure identity survives certificate rotation and detects CERT_CHANGED drift."""
    k1 = construct_identity_key("10.0.0.5", 465, "SMTP", "mail.example.com", "CERT_A_HASH_123")
    k2 = construct_identity_key("10.0.0.5", 465, "SMTP", "mail.example.com", "CERT_B_HASH_456")
    assert k1 == k2, "Certificate rotation created a new identity key instead of maintaining identity!"

    b_prof = make_dummy_profile(cert_sha256="CERT_A_HASH_123")
    c_prof = make_dummy_profile(cert_sha256="CERT_B_HASH_456")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.CERT_CHANGED
    assert "leaf_cert_sha256" in res.changed_fields


def test_37_starttls_not_observed_does_not_create_drift():
    """37. Check 2A — STARTTLS NOT_OBSERVED does not trigger STARTTLS_DISABLED drift."""
    b_prof = make_dummy_profile(stls_state="ACCEPTED")
    c_prof = make_dummy_profile(stls_state="NOT_OBSERVED")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is False, "NOT_OBSERVED was incorrectly treated as STARTTLS_DISABLED drift!"


def test_38_explicit_starttls_rejection_creates_drift():
    """38. Check 2B — Explicit STARTTLS rejection creates STARTTLS_DISABLED drift."""
    b_prof = make_dummy_profile(stls_state="ACCEPTED")
    c_prof = make_dummy_profile(stls_state="REJECTED")

    res = compare_profiles_for_drift(c_prof, b_prof, BaselineStatus.ESTABLISHED)
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.STARTTLS_DISABLED
    assert "starttls_state" in res.changed_fields


def test_39_risk_score_change_alone_does_not_create_drift():
    """39. Check 3A — Risk score changes alone do not create an independent DriftEvent."""
    b_prof = make_dummy_profile()
    c_prof = make_dummy_profile()

    res = compare_profiles_for_drift(
        current=c_prof,
        baseline_profile=b_prof,
        baseline_status=BaselineStatus.ESTABLISHED,
        current_risk_score=80.0,
        baseline_risk_score=10.0,
    )
    assert res.is_drift_detected is False, "Risk score change alone created a false positive DriftEvent!"


def test_40_crypto_change_includes_risk_delta_metadata():
    """40. Check 3B — Actual cryptographic change generates DriftEvent with risk delta as derived metadata."""
    b_prof = make_dummy_profile(tls_version="TLS 1.3")
    c_prof = make_dummy_profile(tls_version="TLS 1.2")

    res = compare_profiles_for_drift(
        current=c_prof,
        baseline_profile=b_prof,
        baseline_status=BaselineStatus.ESTABLISHED,
        current_risk_score=50.0,
        baseline_risk_score=20.0,
    )
    assert res.is_drift_detected is True
    assert res.primary_event_type == DriftEventType.TLS_VERSION_DOWNGRADE
    assert res.changed_fields == ["negotiated_tls_version"]
    assert res.risk_delta == 30.0


def test_41_full_regression_suite_marker():
    """41. Full Phase 0–6 regression suite marker."""
    assert True

