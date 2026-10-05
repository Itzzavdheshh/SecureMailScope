from datetime import datetime, timezone
import base64
import json
import re
from types import SimpleNamespace
import zlib

import pytest
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.db import session as db_session_module
from app.db.session import Base
from app.analyzers.security_fingerprint import (
    build_security_fingerprint,
    compare_security_fingerprints,
)
from app.analyzers.pipeline import run_pipeline
from app.models import AnalysisJob, Capture, EmailSession, InfrastructureIdentity
from app.reports.report_generator import (
    build_report_data_graph,
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)
from app.services.query_service import get_session_by_id


def _pdf_streams(pdf_bytes):
    streams = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\n?endstream", pdf_bytes, re.S):
        try:
            encoded = match.group(1).strip()
            streams.append(zlib.decompress(base64.a85decode(b"<~" + encoded, adobe=True)))
        except (ValueError, zlib.error):
            continue
    return streams


@pytest.fixture
async def fingerprint_database(tmp_path):
    previous_url = settings.database_url
    previous_upload_dir = settings.upload_dir
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    settings.upload_dir = str(upload_dir)
    settings.database_url = f"sqlite+aiosqlite:///{tmp_path / 'fingerprint.db'}"
    db_session_module.engine = create_async_engine(settings.database_url)
    db_session_module.AsyncSessionLocal = async_sessionmaker(
        db_session_module.engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with db_session_module.engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield upload_dir
    await db_session_module.engine.dispose()
    settings.database_url = previous_url
    settings.upload_dir = previous_upload_dir


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


def test_offered_parameter_order_does_not_change_hash():
    first = _fingerprint()
    second = _fingerprint(tls={
        "offered_tls_versions": '["TLS 1.2", "TLS 1.3"]',
        "client_cipher_suites": '["0x1301", "0x1302"]',
    })
    third = _fingerprint(tls={
        "offered_tls_versions": '["TLS 1.3", "TLS 1.2"]',
        "client_cipher_suites": '["0x1302", "0x1301"]',
    })

    assert second["fingerprint_hash"] == third["fingerprint_hash"]
    assert compare_security_fingerprints(second, third)["status"] == "UNCHANGED"


@pytest.mark.parametrize("filename", [
    "01_secure_smtp.pcap",
    "02_deprecated_tls.pcap",
    "03_weak_cipher.pcap",
    "04_expired_certificate.pcap",
])
@pytest.mark.asyncio
async def test_demo_capture_fingerprint_reconstructs_from_persisted_rows_and_reports(
    fingerprint_database, filename
):
    from app.analyzers.baseline import global_baseline_store

    global_baseline_store.clear()
    repository_root = Path(__file__).resolve().parents[2]
    pcap_bytes = (repository_root / "demo_pcaps" / filename).read_bytes()
    pcap_path = fingerprint_database / filename
    pcap_path.write_bytes(pcap_bytes)

    async with db_session_module.AsyncSessionLocal() as db:
        capture = Capture(
            filename=filename,
            file_path=str(pcap_path),
            file_size_bytes=len(pcap_bytes),
            sha256_hash=__import__("hashlib").sha256(pcap_bytes).hexdigest(),
        )
        db.add(capture)
        await db.flush()
        job = AnalysisJob(capture_id=capture.id)
        db.add(job)
        await db.commit()
        await run_pipeline(capture, job, db)
        await db.refresh(job)
        session_id = (await db.execute(
            select(EmailSession.id).where(EmailSession.job_id == job.id)
        )).scalar_one()
        persisted_session = await get_session_by_id(db, session_id)
        infrastructure_id = (await db.execute(
            select(InfrastructureIdentity.id).where(
                InfrastructureIdentity.ip_address == persisted_session.server_ip,
                InfrastructureIdentity.last_evaluated_job_id == job.id,
            )
        )).scalar_one_or_none()
        fingerprint = build_security_fingerprint(
            persisted_session, capture.id, job, infrastructure_id
        )
        graph = await build_report_data_graph(db, job.id)

        assert job.status.value == "COMPLETED"
        assert graph["sessions"][0]["cryptographic_security_fingerprint"] == fingerprint
        assert json.loads(generate_json_report(graph))["sessions"][0]["cryptographic_security_fingerprint"] == fingerprint
        assert fingerprint["security_posture"]["analysis_job_risk_score"] == job.overall_risk_score
        assert fingerprint["stable_profile"]["tls_version"] is not None
        assert fingerprint["fingerprint_hash"].startswith("sha256:")
        assert fingerprint["evidence"]["frames"]["server_hello"] is not None
        assert fingerprint["evidence"]["frames"]["certificate"] is None
        assert fingerprint["fingerprint_hash"] in generate_html_report(graph)
        pdf_text_streams = _pdf_streams(generate_pdf_report(graph))
        assert any(b"Cryptographic Security Fingerprints" in stream for stream in pdf_text_streams)
        assert any(b"Fingerprint Hash" in stream for stream in pdf_text_streams)
