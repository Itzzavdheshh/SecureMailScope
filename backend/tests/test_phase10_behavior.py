"""
Phase 10 Behavioral AI/ML Analysis Audit Test Suite.
Verifies data lineage, categorical feature handling, statistical risk calculations (Z-score & normalized deviation),
Isolation Forest scoring, baseline semantics, double-counting isolation, evidence lineage, and API endpoints.
"""

import json
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.config import settings
from app.main import app
from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    TlsHandshake,
    Certificate,
    Finding,
    BehavioralAnalysis,
    StarttlsStatus,
    ProtocolType,
)
from app.models.infrastructure import InfrastructureIdentity
from app.behavioral.engine import (
    BehavioralAnalysisEngine,
    BehavioralAnalysisResult,
    BehavioralAnomaly,
    DeviationSignificance,
    AnalysisMethodStatus,
    ISOLATION_FOREST_MIN_OBSERVATIONS,
    ZSCORE_MIN_OBSERVATIONS,
)
from app.analyzers.identity import CryptographicProfile
from app.analyzers.baseline import InfrastructureBaseline, BaselineStatus
from app.models.enums import EvidenceStatus


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
        await conn.run_sync(Base.metadata.create_all)

    yield

    await db_session_module.engine.dispose()
    settings.upload_dir = original_upload_dir
    settings.database_url = original_db_url


from app.db.session import Base


def make_profile(**kwargs) -> CryptographicProfile:
    defaults = {
        "protocol": "SMTP",
        "server_ip": "192.168.1.50",
        "server_port": 25,
        "hostname": "mail.test.local",
        "negotiated_tls_version": "TLS 1.3",
        "negotiated_cipher_suite": "TLS_AES_256_GCM_SHA384",
        "forward_secrecy": True,
        "key_exchange_algorithm": "ECDHE",
        "leaf_cert_sha256": "certsha1234567890abcdef",
        "cert_signature_algorithm": "sha256WithRSAEncryption",
        "cert_public_key_type": "RSA",
        "cert_public_key_bits": 2048,
        "cert_self_signed": False,
        "starttls_state": "ACCEPTED",
        "ja3": None,
        "ja3s": None,
    }
    defaults.update(kwargs)
    return CryptographicProfile(**defaults)


@pytest.mark.asyncio
async def test_1_no_baseline_or_provisional_handling():
    """Verify engine returns INSUFFICIENT_EVIDENCE when baseline is provisional or missing."""
    engine = BehavioralAnalysisEngine()
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.PROVISIONAL,
        observation_count=1,
    )
    profile = make_profile()

    res = engine.analyze(
        infrastructure_id="inf-123",
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        job_id="job-123",
        current_profile=profile,
        baseline=baseline,
        current_risk_score=10.0,
    )

    assert res.baseline_status == BaselineStatus.PROVISIONAL
    assert res.overall_status == EvidenceStatus.INSUFFICIENT_EVIDENCE
    assert res.significant_deviation_detected is False
    assert len(res.anomalies) == 0


@pytest.mark.asyncio
async def test_2_stable_baseline_no_false_anomalies():
    """Verify 5 identical secure observations followed by a 6th identical observation produces NO false anomalies."""
    engine = BehavioralAnalysisEngine()

    base_profile = make_profile()
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=base_profile,
        observation_history=[
            {"risk_score": 0.0, "forward_secrecy": True, "negotiated_tls_version": "TLS 1.3"}
            for _ in range(5)
        ],
    )

    res = engine.analyze(
        infrastructure_id="inf-123",
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        job_id="job-124",
        current_profile=base_profile,
        baseline=baseline,
        current_risk_score=0.0,
    )

    assert res.baseline_status == BaselineStatus.ESTABLISHED
    assert res.significant_deviation_detected is False
    assert len(res.anomalies) == 0


@pytest.mark.asyncio
async def test_3_categorical_tls_downgrade():
    """Verify TLS 1.3 -> TLS 1.0 downgrade is flagged as explicit HIGH significance categorical anomaly."""
    engine = BehavioralAnalysisEngine()
    baseline_profile = make_profile(negotiated_tls_version="TLS 1.3")
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=baseline_profile,
    )

    downgraded = make_profile(negotiated_tls_version="TLS 1.0")
    res = engine.analyze(
        infrastructure_id="inf-123",
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        job_id="job-125",
        current_profile=downgraded,
        baseline=baseline,
        current_risk_score=30.0,
    )

    assert res.significant_deviation_detected is True
    assert len(res.anomalies) == 1
    anom = res.anomalies[0]
    assert anom.feature == "negotiated_tls_version"
    assert anom.significance == DeviationSignificance.HIGH
    assert "TLS 1.3 → TLS 1.0" in anom.change_description


@pytest.mark.asyncio
async def test_4_forward_secrecy_loss():
    """Verify loss of forward secrecy (Enabled -> Disabled) is flagged as HIGH significance anomaly."""
    engine = BehavioralAnalysisEngine()
    baseline_profile = make_profile(forward_secrecy=True)
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=baseline_profile,
    )

    no_fs = make_profile(forward_secrecy=False)
    res = engine.analyze(
        infrastructure_id="inf-123",
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        job_id="job-126",
        current_profile=no_fs,
        baseline=baseline,
        current_risk_score=20.0,
    )

    assert res.significant_deviation_detected is True
    fs_anom = next(a for a in res.anomalies if a.feature == "forward_secrecy")
    assert fs_anom.significance == DeviationSignificance.HIGH
    assert fs_anom.baseline_value is True
    assert fs_anom.observed_value is False


@pytest.mark.asyncio
async def test_5_certificate_rotation():
    """Verify certificate fingerprint rotation is reported factually as MEDIUM deviation without calling it malicious."""
    engine = BehavioralAnalysisEngine()
    baseline_profile = make_profile(leaf_cert_sha256="cert_old_hash_1234567890")
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=baseline_profile,
    )

    rotated = make_profile(leaf_cert_sha256="cert_new_hash_9876543210")
    res = engine.analyze(
        infrastructure_id="inf-123",
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        job_id="job-127",
        current_profile=rotated,
        baseline=baseline,
        current_risk_score=0.0,
    )

    cert_anom = next(a for a in res.anomalies if a.feature == "leaf_cert_sha256")
    assert cert_anom.significance == DeviationSignificance.MEDIUM
    assert "Certificate fingerprint changed" in cert_anom.change_description
    assert "rotation" in cert_anom.reason.lower()
    # Confirm no malicious/threat terms
    assert "malicious" not in cert_anom.reason.lower()


@pytest.mark.asyncio
async def test_6_zero_variance_numerical_handling():
    """Verify statistical risk score analysis handles zero variance without producing NaN/Inf."""
    engine = BehavioralAnalysisEngine()
    baseline_profile = make_profile()
    # 5 history observations with identical risk_score = 10.0 (std = 0.0)
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=baseline_profile,
        observation_history=[{"risk_score": 10.0} for _ in range(5)],
    )

    res = engine.analyze(
        infrastructure_id="inf-123",
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        job_id="job-128",
        current_profile=baseline_profile,
        baseline=baseline,
        current_risk_score=10.0,
    )

    assert res.risk_stat_analysis is not None
    stat = res.risk_stat_analysis
    assert stat.method == "NORMALIZED_DEVIATION"
    assert stat.baseline_mean == 10.0
    assert stat.baseline_std is None
    assert stat.zscore is None
    assert stat.normalized_deviation == 0.0
    assert "baseline variance is zero" in stat.interpretation


@pytest.mark.asyncio
async def test_7_isolation_forest_execution_and_threshold():
    """Verify Isolation Forest is SKIPPED/INSUFFICIENT when n < 10 and EXECUTED deterministically when n >= 10."""
    engine = BehavioralAnalysisEngine()
    base_profile = make_profile()

    # n = 5 (< 10)
    baseline_small = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=base_profile,
        observation_history=[
            {"risk_score": 10.0, "forward_secrecy": True, "negotiated_tls_version": "TLS 1.3"}
            for _ in range(5)
        ],
    )
    res_small = engine.analyze("inf-1", "key-1", "job-1", base_profile, baseline_small, 10.0)
    assert res_small.isolation_forest is not None
    assert res_small.isolation_forest.method_status == AnalysisMethodStatus.INSUFFICIENT_DATA

    # n = 12 (>= 10)
    baseline_large = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=12,
        profile=base_profile,
        observation_history=[
            {"risk_score": 10.0, "forward_secrecy": True, "negotiated_tls_version": "TLS 1.3"}
            for _ in range(12)
        ],
    )
    res_large_1 = engine.analyze("inf-1", "key-1", "job-2", base_profile, baseline_large, 10.0)
    res_large_2 = engine.analyze("inf-1", "key-1", "job-3", base_profile, baseline_large, 10.0)

    assert res_large_1.isolation_forest.method_status == AnalysisMethodStatus.COMPLETED
    assert res_large_1.isolation_forest.normalized_anomaly_score is not None
    # Determinism check (random_state=42)
    assert res_large_1.isolation_forest.normalized_anomaly_score == res_large_2.isolation_forest.normalized_anomaly_score


@pytest.mark.asyncio
async def test_8_risk_only_change_isolation():
    """Verify risk score increase alone does NOT produce false categorical cryptographic anomalies."""
    engine = BehavioralAnalysisEngine()
    base_profile = make_profile()
    baseline = InfrastructureBaseline(
        identity_key="smtp:192.168.1.50:25:mail.test.local",
        status=BaselineStatus.ESTABLISHED,
        observation_count=5,
        profile=base_profile,
        observation_history=[{"risk_score": 5.0} for _ in range(5)],
    )

    # Current profile is identical to baseline, but current risk score is higher
    res = engine.analyze("inf-1", "key-1", "job-4", base_profile, baseline, current_risk_score=40.0)

    # No categorical cryptographic anomalies should exist
    assert len(res.anomalies) == 0


@pytest.mark.asyncio
async def test_9_behavior_api_endpoints():
    """Test GET /api/v1/behavior REST API endpoints."""
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        capture = Capture(
            filename="api_behavior.pcap",
            file_path="/tmp/api_behavior.pcap",
            file_size_bytes=2048,
            sha256_hash="api_behavior_hash",
        )
        session.add(capture)
        await session.commit()
        await session.refresh(capture)

        job = AnalysisJob(capture_id=capture.id, status="COMPLETED")
        session.add(job)
        await session.commit()
        await session.refresh(job)

        infra = InfrastructureIdentity(
            ip_address="192.168.1.50",
            hostname="mail.test.local",
        )
        session.add(infra)
        await session.commit()
        await session.refresh(infra)

        behavior = BehavioralAnalysis(
            infrastructure_id=infra.id,
            job_id=job.id,
            identity_key="smtp:192.168.1.50:25:mail.test.local",
            baseline_status="ESTABLISHED",
            observation_count=10,
            significant_deviation_detected=True,
            deviation_summary="Significant cryptographic behavioural deviation detected.",
            anomalies_json=json.dumps([
                {
                    "feature": "negotiated_tls_version",
                    "baseline_value": "TLS 1.3",
                    "observed_value": "TLS 1.0",
                    "change_description": "Downgraded from TLS 1.3 to TLS 1.0",
                    "significance": "HIGH",
                    "reason": "Protocol downgrade detected",
                    "evidence_status": "ANALYZED",
                    "method": "CATEGORICAL_CHANGE",
                }
            ]),
            anomaly_count=1,
        )
        session.add(behavior)
        await session.commit()
        await session.refresh(behavior)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # GET /api/v1/behavior
        res = await client.get("/api/v1/behavior")
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert len(data["items"]) >= 1

        # GET /api/v1/behavior/{id}
        res = await client.get(f"/api/v1/behavior/{behavior.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == str(behavior.id)
        assert data["job_id"] == str(job.id)

        # GET /api/v1/behavior/jobs/{job_id}/summary
        res = await client.get(f"/api/v1/behavior/jobs/{job.id}/summary")
        assert res.status_code == 200
        data = res.json()
        assert data["job_id"] == str(job.id)
        assert data["total_analyses"] >= 1
