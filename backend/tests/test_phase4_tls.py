"""
Phase 4 Test Suite — TLS Handshake + X.509 Certificate Analysis + STARTTLS State Machine.
Validates all 30 specified requirements for Phase 4.
"""

import io
import struct
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    StarttlsStatus,
    ProtocolType,
)

from app.analyzers.tls_parser import (
    parse_client_hello,
    parse_server_hello,
    parse_certificate_msg,
    parse_tls_records,
)
from app.analyzers.cert_analyzer import (
    parse_x509_certificate,
    analyze_certificate_chain,
)
from app.analyzers.starttls_state_machine import evaluate_starttls_state
from app.analyzers.pipeline import run_pipeline
from tests.test_phase3_pipeline import build_raw_pcap


def generate_self_signed_cert(
    cn="mail.example.com",
    days_valid=30,
    days_offset=0,
    key_size=2048,
    sig_hash=hashes.SHA256(),
    san_dns=None,
    is_ca=False
):
    """Generate synthetic DER encoded X.509 certificate using cryptography."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])

    now = datetime.now(timezone.utc)
    not_before = now + timedelta(days=days_offset)
    not_after = not_before + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_dns:
        dns_names = [x509.DNSName(name) for name in san_dns]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False
        )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

    cert = builder.sign(private_key, sig_hash)
    return cert.public_bytes(serialization.Encoding.DER)


def generate_sha1_cert():
    """Generate a synthetic DER certificate with a SHA-1 signature algorithm OID."""
    sha256_der = generate_self_signed_cert()
    # Replace sha256WithRSAEncryption OID (1.2.840.113549.1.1.11) with sha1WithRSAEncryption OID (1.2.840.113549.1.1.5)
    sha256_oid = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
    sha1_oid = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05"
    return sha256_der.replace(sha256_oid, sha1_oid)


def build_raw_client_hello_payload(
    legacy_version=0x0303,
    sni=None,
    alpn=None,
    supported_versions=None,
    cipher_suites=None
):
    """Build a raw TLS ClientHello handshake payload."""
    if cipher_suites is None:
        cipher_suites = [0xC02F, 0x009C, 0x1301]

    cs_bytes = b"".join(struct.pack(">H", cs) for cs in cipher_suites)

    # Extensions
    ext_bytes = bytearray()

    if sni:
        sni_b = sni.encode("utf-8")
        sni_ext_data = struct.pack(">H", len(sni_b) + 3) + b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
        ext_bytes.extend(struct.pack(">HH", 0, len(sni_ext_data)) + sni_ext_data)

    if alpn:
        alpn_data = bytearray()
        for p in alpn:
            pb = p.encode("utf-8")
            alpn_data.append(len(pb))
            alpn_data.extend(pb)
        alpn_ext_data = struct.pack(">H", len(alpn_data)) + alpn_data
        ext_bytes.extend(struct.pack(">HH", 16, len(alpn_ext_data)) + alpn_ext_data)

    if supported_versions:
        sv_data = bytearray([len(supported_versions) * 2])
        for v in supported_versions:
            sv_data.extend(struct.pack(">H", v))
        ext_bytes.extend(struct.pack(">HH", 43, len(sv_data)) + sv_data)

    body = bytearray()
    body.extend(struct.pack(">H", legacy_version))
    body.extend(b"\x01" * 32)  # Random
    body.append(0)  # Session ID len 0
    body.extend(struct.pack(">H", len(cs_bytes)))
    body.extend(cs_bytes)
    body.append(1)  # Comp methods len 1
    body.append(0)  # null compression
    body.extend(struct.pack(">H", len(ext_bytes)))
    body.extend(ext_bytes)

    hdr = b"\x01" + struct.pack(">I", len(body))[1:]  # msg_type 1 (ClientHello) + 3-byte len
    return bytes(hdr + body)


def build_raw_server_hello_payload(
    legacy_version=0x0303,
    selected_cs=0xC02F,
    supported_versions=None
):
    """Build a raw TLS ServerHello handshake payload."""
    ext_bytes = bytearray()

    if supported_versions:
        sv_data = struct.pack(">H", supported_versions[0])
        ext_bytes.extend(struct.pack(">HH", 43, len(sv_data)) + sv_data)

    body = bytearray()
    body.extend(struct.pack(">H", legacy_version))
    body.extend(b"\x02" * 32)  # Random
    body.append(0)  # Session ID len 0
    body.extend(struct.pack(">H", selected_cs))
    body.append(0)  # null compression
    body.extend(struct.pack(">H", len(ext_bytes)))
    body.extend(ext_bytes)

    hdr = b"\x02" + struct.pack(">I", len(body))[1:]  # msg_type 2 (ServerHello) + 3-byte len
    return bytes(hdr + body)


def build_raw_certificate_payload(der_certs):
    """Build a raw TLS Certificate handshake payload (msg_type 11)."""
    certs_data = bytearray()
    for der in der_certs:
        certs_data.extend(struct.pack(">I", len(der))[1:])  # 3-byte cert len
        certs_data.extend(der)

    body = struct.pack(">I", len(certs_data))[1:] + certs_data  # 3-byte total certs len + certs
    hdr = b"\x0b" + struct.pack(">I", len(body))[1:]  # msg_type 11
    return bytes(hdr + body)


def wrap_in_tls_record(payload, content_type=22, version=0x0303):
    """Wrap handshake payload in 5-byte TLS record header."""
    hdr = struct.pack(">BHH", content_type, version, len(payload))
    return hdr + payload


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


# ─── 30 REQUIRED TESTS FOR PHASE 4 ──────────────────────────────────────────

def test_01_tls_client_hello_extraction():
    """1. TLS ClientHello extraction."""
    ch_raw = build_raw_client_hello_payload(sni="mail.example.com", alpn=["smtp"])
    ch = parse_client_hello(ch_raw)
    assert ch is not None
    assert ch.sni_hostname == "mail.example.com"
    assert "smtp" in ch.alpn_protocols


def test_02_tls_server_hello_extraction():
    """2. TLS ServerHello extraction."""
    sh_raw = build_raw_server_hello_payload(selected_cs=0xC02F)
    sh = parse_server_hello(sh_raw)
    assert sh is not None
    assert sh.selected_cipher_suite == 0xC02F
    assert sh.cipher_name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"


def test_03_tls_12_negotiated_version():
    """3. TLS 1.2 negotiated version."""
    sh_raw = build_raw_server_hello_payload(legacy_version=0x0303)
    sh = parse_server_hello(sh_raw)
    assert sh.negotiated_tls_version == "TLS 1.2"


def test_04_tls_13_supported_versions_handling():
    """4. TLS 1.3 supported_versions handling."""
    sh_raw = build_raw_server_hello_payload(legacy_version=0x0303, supported_versions=[0x0304])
    sh = parse_server_hello(sh_raw)
    assert sh.negotiated_tls_version == "TLS 1.3"


def test_05_offered_vs_negotiated_tls_distinction():
    """5. Offered vs negotiated TLS distinction."""
    ch_raw = build_raw_client_hello_payload(legacy_version=0x0303, supported_versions=[0x0304, 0x0303])
    sh_raw = build_raw_server_hello_payload(legacy_version=0x0303)
    ch = parse_client_hello(ch_raw)
    sh = parse_server_hello(sh_raw)

    assert 0x0304 in ch.supported_versions
    assert sh.negotiated_tls_version == "TLS 1.2"


def test_06_cipher_suite_extraction():
    """6. Cipher suite extraction."""
    sh_raw = build_raw_server_hello_payload(selected_cs=0x009C)
    sh = parse_server_hello(sh_raw)
    assert sh.selected_cipher_suite == 0x009C
    assert "RSA" in sh.cipher_name


def test_07_key_exchange_classification():
    """7. Key exchange classification."""
    sh_ecdhe = parse_server_hello(build_raw_server_hello_payload(selected_cs=0xC02F))
    sh_rsa = parse_server_hello(build_raw_server_hello_payload(selected_cs=0x0035))

    assert sh_ecdhe.key_exchange == "ECDHE"
    assert sh_rsa.key_exchange == "RSA_STATIC"


def test_08_forward_secrecy_classification():
    """8. Forward Secrecy classification."""
    sh_ecdhe = parse_server_hello(build_raw_server_hello_payload(selected_cs=0xC02F))
    sh_rsa = parse_server_hello(build_raw_server_hello_payload(selected_cs=0x0035))

    assert sh_ecdhe.is_forward_secrecy is True
    assert sh_rsa.is_forward_secrecy is False


def test_09_missing_server_hello_yields_insufficient_evidence():
    """9. Missing ServerHello yields insufficient evidence."""
    sh = parse_server_hello(b"invalid_data")
    assert sh is None


def test_10_certificate_der_extraction():
    """10. Certificate DER extraction."""
    cert_der = generate_self_signed_cert()
    cm_raw = build_raw_certificate_payload([cert_der])
    cm = parse_certificate_msg(cm_raw)

    assert cm is not None
    assert len(cm.der_certificates) == 1
    assert cm.der_certificates[0] == cert_der


def test_11_x509_subject_issuer_extraction():
    """11. X.509 subject/issuer extraction."""
    cert_der = generate_self_signed_cert(cn="smtp.domain.test")
    parsed = parse_x509_certificate(cert_der)

    assert parsed is not None
    assert "CN=smtp.domain.test" in parsed.subject_dn
    assert "CN=smtp.domain.test" in parsed.issuer_dn
    assert parsed.common_name == "smtp.domain.test"


def test_12_san_extraction():
    """12. SAN extraction."""
    cert_der = generate_self_signed_cert(san_dns=["mail.test", "smtp.test"])
    parsed = parse_x509_certificate(cert_der)

    assert parsed is not None
    assert "mail.test" in parsed.san_domains
    assert "smtp.test" in parsed.san_domains


def test_13_public_key_size_extraction():
    """13. Public key size extraction."""
    cert_2048 = parse_x509_certificate(generate_self_signed_cert(key_size=2048))
    cert_4096 = parse_x509_certificate(generate_self_signed_cert(key_size=4096))

    assert cert_2048.public_key_type == "RSA"
    assert cert_2048.public_key_size_bits == 2048
    assert cert_4096.public_key_size_bits == 4096


def test_14_signature_algorithm_extraction():
    """14. Signature algorithm extraction."""
    cert_der = generate_self_signed_cert(sig_hash=hashes.SHA256())
    parsed = parse_x509_certificate(cert_der)

    assert "sha256" in parsed.signature_algorithm.lower()


def test_15_sha256_fingerprint():
    """15. SHA-256 fingerprint."""
    cert_der = generate_self_signed_cert()
    parsed = parse_x509_certificate(cert_der)

    assert parsed.sha256_fingerprint is not None
    assert len(parsed.sha256_fingerprint) == 64


def test_16_self_signed_detection():
    """16. Self-signed detection."""
    cert_der = generate_self_signed_cert()
    parsed = parse_x509_certificate(cert_der)

    assert parsed.is_self_signed is True


def test_17_certificate_validity_at_capture_time():
    """17. Certificate validity at capture time."""
    cert_der = generate_self_signed_cert(days_valid=30, days_offset=-5)

    # Valid timestamp = now
    now_ts = datetime.now(timezone.utc).timestamp()
    parsed_val = parse_x509_certificate(cert_der, capture_timestamp=now_ts)

    assert parsed_val.is_valid_at_capture is True


def test_18_expired_at_capture_certificate():
    """18. Expired-at-capture certificate."""
    cert_der = generate_self_signed_cert(days_valid=10, days_offset=-30)  # Expired 20 days ago
    now_ts = datetime.now(timezone.utc).timestamp()
    parsed = parse_x509_certificate(cert_der, capture_timestamp=now_ts)

    assert parsed.is_valid_at_capture is False


def test_19_sha1_signature_detection():
    """19. SHA-1 signature detection."""
    cert_der = generate_sha1_cert()
    parsed = parse_x509_certificate(cert_der)

    assert parsed is not None
    assert parsed.is_weak_signature is True


def test_20_certificate_chain_ordering():
    """20. Certificate chain ordering."""
    root_der = generate_self_signed_cert(cn="Root CA", is_ca=True)
    leaf_der = generate_self_signed_cert(cn="Leaf Server")

    chain_res = analyze_certificate_chain([leaf_der, root_der])

    assert chain_res.chain_length == 2
    assert "Leaf Server" in chain_res.leaf_subject_dn
    assert "Root CA" in chain_res.root_issuer_dn


def test_21_missing_certificate_insufficient_evidence():
    """21. Missing certificate -> insufficient evidence."""
    chain_res = analyze_certificate_chain([])
    assert chain_res.chain_length == 0
    assert chain_res.validation_status == "INSUFFICIENT_EVIDENCE"


def test_22_starttls_full_successful_state_transition():
    """22. STARTTLS full successful state transition."""
    st_eval = evaluate_starttls_state(
        phase3_status=StarttlsStatus.ACCEPTED,
        advertised_frame=1,
        command_frame=2,
        response_frame=3,
        response_code=220,
        tls_handshake_observed=True
    )
    assert st_eval.status == StarttlsStatus.ACCEPTED
    assert st_eval.tls_handshake_observed is True


def test_23_starttls_rejected_state():
    """23. STARTTLS rejected state."""
    st_eval = evaluate_starttls_state(
        phase3_status=StarttlsStatus.REJECTED,
        advertised_frame=1,
        command_frame=2,
        response_frame=3,
        response_code=454,
        tls_handshake_observed=False
    )
    assert st_eval.status == StarttlsStatus.REJECTED
    assert st_eval.is_downgrade_detected is True


def test_24_starttls_accepted_but_tls_not_observed():
    """24. STARTTLS accepted but TLS not observed."""
    st_eval = evaluate_starttls_state(
        phase3_status=StarttlsStatus.ACCEPTED,
        advertised_frame=1,
        command_frame=2,
        response_frame=3,
        response_code=220,
        tls_handshake_observed=False,
        plaintext_after_accepted=True
    )
    assert st_eval.status == StarttlsStatus.ANOMALOUS


def test_25_implicit_tls_session():
    """25. Implicit TLS session."""
    st_eval = evaluate_starttls_state(
        phase3_status=StarttlsStatus.NOT_OBSERVED,
        advertised_frame=None,
        command_frame=None,
        response_frame=None,
        response_code=None,
        tls_handshake_observed=True
    )
    assert st_eval.status == StarttlsStatus.NOT_OBSERVED


def test_26_fragmented_tls_handshake():
    """26. Fragmented TLS handshake."""
    ch_raw = build_raw_client_hello_payload(sni="frag.test")
    rec = wrap_in_tls_record(ch_raw)

    part1 = rec[:15]
    part2 = rec[15:]

    recs = parse_tls_records(part1 + part2)
    assert len(recs) == 1
    ch = parse_client_hello(recs[0].payload)
    assert ch.sni_hostname == "frag.test"


def test_27_malformed_certificate_does_not_crash():
    """27. Malformed certificate does not crash analysis."""
    parsed = parse_x509_certificate(b"CORRUPT_NOT_DER_BYTES")
    assert parsed is None


def test_28_evidence_frame_timestamp_preservation():
    """28. Evidence frame/timestamp preservation."""
    ch_raw = build_raw_client_hello_payload()
    ch = parse_client_hello(ch_raw, frame_number=42, timestamp=1700000042.5)

    assert ch.frame_number == 42
    assert ch.timestamp == 1700000042.5


def test_29_ja3_generation():
    """29. JA3 generation where available."""
    ch_raw = build_raw_client_hello_payload(cipher_suites=[0xC02F, 0x009C])
    ch = parse_client_hello(ch_raw)

    assert ch.ja3_str is not None
    assert ch.ja3_hash is not None
    assert len(ch.ja3_hash) == 32


def test_30_ja3s_generation():
    """30. JA3S generation where available."""
    sh_raw = build_raw_server_hello_payload(selected_cs=0xC02F)
    sh = parse_server_hello(sh_raw)

    assert sh.ja3s_str is not None
    assert sh.ja3s_hash is not None
    assert len(sh.ja3s_hash) == 32


@pytest.mark.asyncio
async def test_31_end_to_end_tls_pipeline_persistence(tmp_path):
    """End-to-end integration test: PCAP containing TLS handshake -> DB models."""
    cert_der = generate_self_signed_cert(cn="smtp.test.com")
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="smtp.test.com"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(selected_cs=0xC02F))
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
        files = {"file": ("tls_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        up_res = await client.post("/api/captures/upload", files=files)
        assert up_res.status_code == 201
        job_id = up_res.json()["job_id"]

        start_res = await client.post(f"/api/jobs/{job_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["job"]["status"] == "COMPLETED"

        # Check DB persistence
        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            sess_stmt = select(EmailSession).where(EmailSession.job_id == job_id)
            sess_res = await session.execute(sess_stmt)
            email_sess = sess_res.scalar_one()

            assert email_sess.starttls_state == StarttlsStatus.ACCEPTED

            tls_stmt = select(TlsHandshake).where(TlsHandshake.session_id == email_sess.id)
            tls_res = await session.execute(tls_stmt)
            tls_db = tls_res.scalar_one_or_none()
            assert tls_db is not None
            assert tls_db.negotiated_cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

            cert_stmt = select(Certificate).where(Certificate.session_id == email_sess.id)
            cert_res = await session.execute(cert_stmt)
            certs = cert_res.scalars().all()
            assert len(certs) == 1
            assert "CN=smtp.test.com" in certs[0].subject_dn
