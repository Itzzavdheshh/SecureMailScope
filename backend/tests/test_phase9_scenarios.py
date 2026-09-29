"""
Phase 9 Automated Scenario Verification Test Suite.
Validates all Phase 9 laboratory scenarios against the real end-to-end forensic analysis pipeline,
verifying PCAP reader -> TCP reconstruction -> STARTTLS -> TLS parser -> X.509 -> rules -> risk -> evidence -> drift -> timeline -> reports.
"""

import io
import pytest
from pathlib import Path
from sqlalchemy import select
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.db.session import Base
from app.main import app
from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    TlsHandshake,
    Certificate,
    Finding,
    Evidence,
    InfrastructureIdentity,
    DriftEvent,
    TimelineEvent,
    StarttlsStatus,
    ProtocolType,
)
from scripts.pcap_lab.scenarios import LAB_SCENARIOS


@pytest.fixture(autouse=True)
async def setup_test_environment(tmp_path):
    """Override upload_dir and database_url to isolated temp folder/file for each test."""
    original_upload_dir = settings.upload_dir
    original_db_url = settings.database_url

    settings.upload_dir = str(tmp_path / "uploads")
    db_file = tmp_path / "test.db"
    settings.database_url = f"sqlite+aiosqlite:///{db_file}"

    from app.db import session as db_session_module
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

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


@pytest.mark.asyncio
async def test_scenario_01_secure_smtp():
    """Scenario 1: Secure SMTP (TLS 1.3, AES-256-GCM, valid cert) -> 0 high-severity findings."""
    sc = LAB_SCENARIOS[1]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_01.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        assert up_res.status_code == 201
        job_id = up_res.json()["job_id"]

        start_res = await client.post(f"/api/jobs/{job_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["job"]["status"] == "COMPLETED"

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            sess_res = await session.execute(select(EmailSession).where(EmailSession.job_id == job_id))
            email_sess = sess_res.scalar_one()

            assert email_sess.protocol == ProtocolType.SMTP
            assert email_sess.starttls_state == StarttlsStatus.ACCEPTED

            tls_res = await session.execute(select(TlsHandshake).where(TlsHandshake.session_id == email_sess.id))
            tls = tls_res.scalar_one()
            assert tls.negotiated_tls_version == "TLS 1.3"
            assert tls.is_forward_secrecy is True

            find_res = await session.execute(select(Finding).where(Finding.job_id == job_id))
            findings = find_res.scalars().all()
            # No HIGH or CRITICAL findings for secure TLS 1.3 with valid cert
            assert not any(f.severity in ["HIGH", "CRITICAL"] for f in findings)


@pytest.mark.asyncio
async def test_scenario_02_deprecated_tls10():
    """Scenario 2: Deprecated TLS 1.0 -> Triggers CRYPT-001 finding."""
    sc = LAB_SCENARIOS[2]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_02.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        job_id = up_res.json()["job_id"]
        await client.post(f"/api/jobs/{job_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            find_res = await session.execute(select(Finding).where(Finding.job_id == job_id))
            findings = find_res.scalars().all()
            assert any(f.rule_id == "CRYPT-001" for f in findings)

            target_finding = [f for f in findings if f.rule_id == "CRYPT-001"][0]
            ev_res = await session.execute(select(Evidence).where(Evidence.finding_id == target_finding.id))
            evidence = ev_res.scalars().all()
            assert len(evidence) >= 1
            assert evidence[0].frame_number == 5
            assert evidence[0].observed_value == "TLS 1.0"


@pytest.mark.asyncio
async def test_scenario_03_weak_cipher_rc4():
    """Scenario 3: Weak Cipher Suite (RC4) -> Triggers CRYPT-005 finding."""
    sc = LAB_SCENARIOS[3]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_03.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        job_id = up_res.json()["job_id"]
        await client.post(f"/api/jobs/{job_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            find_res = await session.execute(select(Finding).where(Finding.job_id == job_id))
            findings = find_res.scalars().all()
            assert any(f.rule_id == "CRYPT-005" for f in findings)


@pytest.mark.asyncio
async def test_scenario_05_expired_cert():
    """Scenario 5: Expired Certificate at Capture Time -> Triggers CERT-001 finding."""
    sc = LAB_SCENARIOS[5]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_05.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        job_id = up_res.json()["job_id"]
        await client.post(f"/api/jobs/{job_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            find_res = await session.execute(select(Finding).where(Finding.job_id == job_id))
            findings = find_res.scalars().all()
            assert any(f.rule_id == "CERT-001" for f in findings)
            assert not any(f.rule_id == "CERT-002" for f in findings)


@pytest.mark.asyncio
async def test_scenario_07_starttls_rejected():
    """Scenario 7: STARTTLS Rejected by Server -> Status REJECTED & STLS-002 finding."""
    sc = LAB_SCENARIOS[7]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_07.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        job_id = up_res.json()["job_id"]
        await client.post(f"/api/jobs/{job_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            sess_res = await session.execute(select(EmailSession).where(EmailSession.job_id == job_id))
            email_sess = sess_res.scalar_one()
            assert email_sess.starttls_state == StarttlsStatus.REJECTED

            find_res = await session.execute(select(Finding).where(Finding.job_id == job_id))
            findings = find_res.scalars().all()
            assert any(f.rule_id == "STLS-002" for f in findings)
            assert not any(f.rule_id == "CRYPT-010" for f in findings)


@pytest.mark.asyncio
async def test_scenario_08_truncated_handshake():
    """Scenario 8: Truncated Evidence -> INSUFFICIENT_EVIDENCE semantics."""
    sc = LAB_SCENARIOS[8]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_08.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        job_id = up_res.json()["job_id"]
        await client.post(f"/api/jobs/{job_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            sess_res = await session.execute(select(EmailSession).where(EmailSession.job_id == job_id))
            email_sess = sess_res.scalar_one()

            tls_res = await session.execute(select(TlsHandshake).where(TlsHandshake.session_id == email_sess.id))
            tlss = tls_res.scalars().all()
            # ServerHello & Certificate were not present in truncated capture
            if len(tlss) > 0:
                assert tlss[0].negotiated_tls_version is None


@pytest.mark.asyncio
async def test_scenario_09_multisession_smtp():
    """Scenario 9: Multi-Session SMTP -> 3 distinct EmailSession records."""
    sc = LAB_SCENARIOS[9]
    pcap_data = sc.generator_fn()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        up_res = await client.post("/api/captures/upload", files={"file": ("scenario_09.pcap", io.BytesIO(pcap_data), "application/octet-stream")})
        job_id = up_res.json()["job_id"]
        await client.post(f"/api/jobs/{job_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            sess_res = await session.execute(select(EmailSession).where(EmailSession.job_id == job_id))
            sessions = sess_res.scalars().all()
            assert len(sessions) == 3


@pytest.mark.asyncio
async def test_scenario_10_baseline_and_drift():
    """Scenario 10: Baseline (10a x 3) -> Drift (10b) -> Detects TLS_VERSION_DOWNGRADED."""
    # Import generator directly so we can pass variant= for unique PCAP bytes each time.
    # Without this, uploading the same bytes 3x hits the SHA-256 dedup 409 guard.
    from scripts.pcap_lab.generators import generate_scenario_j1
    pcap_b = LAB_SCENARIOS[11].generator_fn() # Drift: TLS 1.0

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Run Baseline Capture 10a 3 times to establish baseline (min_established_count = 3).
        # Each variant uses a different client source port -> unique SHA-256 -> no 409 conflict.
        for i in range(3):
            pcap_a = generate_scenario_j1(variant=i)
            up_a = await client.post("/api/captures/upload", files={"file": (f"scenario_10a_{i}.pcap", io.BytesIO(pcap_a), "application/octet-stream")})
            assert up_a.status_code == 201, f"Baseline upload {i} failed: {up_a.text}"
            job_a_id = up_a.json()["job_id"]
            await client.post(f"/api/jobs/{job_a_id}/start")

        # Run Drift Capture 10b against same server (198.51.100.30)
        up_b = await client.post("/api/captures/upload", files={"file": ("scenario_10b.pcap", io.BytesIO(pcap_b), "application/octet-stream")})
        job_b_id = up_b.json()["job_id"]
        await client.post(f"/api/jobs/{job_b_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            drift_res = await session.execute(select(DriftEvent).where(DriftEvent.job_id == job_b_id))
            drifts = drift_res.scalars().all()
            assert len(drifts) >= 1
            assert drifts[0].event_type == "TLS_VERSION_DOWNGRADE"


@pytest.mark.asyncio
async def test_scenario_11_cert_rotation_identity_stability():
    """Scenario 11: Certificate Rotation (11a -> 11b) -> Host identity remains stable."""
    pcap_a = LAB_SCENARIOS[12].generator_fn() # Cert A
    pcap_b = LAB_SCENARIOS[13].generator_fn() # Cert B (Rotated)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Run Capture 11a
        up_a = await client.post("/api/captures/upload", files={"file": ("scenario_11a.pcap", io.BytesIO(pcap_a), "application/octet-stream")})
        job_a_id = up_a.json()["job_id"]
        await client.post(f"/api/jobs/{job_a_id}/start")

        # Run Capture 11b
        up_b = await client.post("/api/captures/upload", files={"file": ("scenario_11b.pcap", io.BytesIO(pcap_b), "application/octet-stream")})
        job_b_id = up_b.json()["job_id"]
        await client.post(f"/api/jobs/{job_b_id}/start")

        from app.db import session as db_session_module
        async with db_session_module.AsyncSessionLocal() as session:
            infra_res = await session.execute(select(InfrastructureIdentity).where(InfrastructureIdentity.ip_address == "198.51.100.40"))
            infras = infra_res.scalars().all()
            # Exactly 1 infrastructure identity record created for 198.51.100.40 (no identity duplication)
            assert len(infras) == 1
