"""
Phase 2 Intake & Ingestion Verification Test Suite.
Verifies all 17 Phase 2 requirements: PCAP/PCAPNG uploading, magic bytes validation,
SHA-256 calculation, duplicate rejection, file size limits, path traversal safety,
metadata extraction, database persistence, and cleanup of failed uploads.
"""

import hashlib
import io
import os
import struct
import tempfile
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.db.session import Base, init_db
from app.main import app
from app.services.capture_service import sanitize_filename, ingest_pcap_upload
from app.utils.pcap_inspector import detect_pcap_format, inspect_pcap_file


def create_minimal_pcap_bytes(tag: int = 0) -> bytes:
    """Generate a valid microsecond LE PCAP byte stream with 2 packets."""
    # Global Header (24 bytes)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Packet 1 Header (16 bytes) + Payload (42 bytes Ethernet+IP+TCP header)
    ts1_sec, ts1_usec = 1700000000 + tag, 100000
    pkt1_data = bytes([tag % 256]) * 42
    pkt1_hdr = struct.pack("<IIII", ts1_sec, ts1_usec, len(pkt1_data), len(pkt1_data))

    # Packet 2 Header (16 bytes)
    ts2_sec, ts2_usec = 1700000005 + tag, 500000
    pkt2_data = bytes([(tag + 1) % 256]) * 42
    pkt2_hdr = struct.pack("<IIII", ts2_sec, ts2_usec, len(pkt2_data), len(pkt2_data))

    return global_hdr + pkt1_hdr + pkt1_data + pkt2_hdr + pkt2_data


def create_minimal_pcapng_bytes(tag: int = 0) -> bytes:
    """Generate a valid minimal PCAPNG byte stream with Section Header Block."""
    # SHB (28 bytes): Type=0x0A0D0D0A, Length=28, BOM=0x1A2B3C4D, Major=1, Minor=0, SectionLen=-1, Length=28
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    return shb + bytes([tag % 256]) * 4





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
async def test_01_valid_pcap_upload_succeeds():
    """1. Valid PCAP upload succeeds."""
    pcap_data = create_minimal_pcap_bytes(1)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("test_capture.pcap", io.BytesIO(pcap_data), "application/vnd.tcpdump.pcap")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 201
        data = response.json()
        assert "capture" in data
        assert data["capture"]["filename"] == "test_capture.pcap"
        assert data["job_status"] == "PENDING"


@pytest.mark.asyncio
async def test_02_valid_pcapng_upload_succeeds():
    """2. Valid PCAPNG upload succeeds."""
    pcapng_data = create_minimal_pcapng_bytes(2)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("network.pcapng", io.BytesIO(pcapng_data), "application/x-pcapng")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 201
        data = response.json()
        assert data["capture"]["filename"] == "network.pcapng"


@pytest.mark.asyncio
async def test_03_sha256_matches_independently_calculated_hash():
    """3. SHA-256 matches independently calculated hash."""
    pcap_data = create_minimal_pcap_bytes(3)
    expected_hash = hashlib.sha256(pcap_data).hexdigest()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("hash_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 201
        assert response.json()["capture"]["sha256_hash"] == expected_hash


@pytest.mark.asyncio
async def test_04_file_size_recorded_correctly():
    """4. File size is recorded correctly."""
    pcap_data = create_minimal_pcap_bytes(4)
    expected_size = len(pcap_data)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("size_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 201
        assert response.json()["capture"]["file_size_bytes"] == expected_size


@pytest.mark.asyncio
async def test_05_duplicate_sha256_handled_correctly():
    """5. Duplicate SHA-256 is handled correctly (HTTP 409 Conflict)."""
    pcap_data = create_minimal_pcap_bytes(5)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files1 = {"file": ("dup1.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        res1 = await client.post("/api/captures/upload", files=files1)
        assert res1.status_code == 201

        files2 = {"file": ("dup2.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        res2 = await client.post("/api/captures/upload", files=files2)
        assert res2.status_code == 409
        assert "Duplicate capture" in res2.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_06_invalid_extension_rejected():
    """6. Invalid extension is rejected (HTTP 400 Bad Request)."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("malicious.exe", io.BytesIO(b"MZ1234567890"), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 400
        assert "Invalid file extension" in response.json()["detail"]


@pytest.mark.asyncio
async def test_07_invalid_magic_bytes_rejected():
    """7. Invalid magic bytes are rejected (HTTP 400 Bad Request)."""
    fake_pcap = b"THIS_IS_NOT_A_REAL_PCAP_FILE_FORMAT_HEADER_DATA"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("corrupt.pcap", io.BytesIO(fake_pcap), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 400
        assert "Unrecognized PCAP magic bytes" in response.json()["detail"]


@pytest.mark.asyncio
async def test_08_oversized_file_rejected(monkeypatch):
    """8. Oversized file is rejected (HTTP 413 Payload Too Large)."""
    settings.max_upload_size_mb = 1
    oversized_data = create_minimal_pcap_bytes(8) + (b"\x00" * (2 * 1024 * 1024))

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("huge.pcap", io.BytesIO(oversized_data), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 413
        assert "exceeds maximum" in response.json()["detail"]


@pytest.mark.asyncio
async def test_09_path_traversal_filename_sanitized():
    """9. Path traversal filename cannot escape storage directory."""
    raw_traversal_name = "../../../etc/passwd.pcap"
    sanitized = sanitize_filename(raw_traversal_name)
    assert "/" not in sanitized
    assert ".." not in sanitized

    pcap_data = create_minimal_pcap_bytes(9)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("../../etc/passwd.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 201
        assert response.json()["capture"]["filename"] == "passwd.pcap"


@pytest.mark.asyncio
async def test_10_capture_database_record_created():
    """10. Capture database record is created correctly."""
    pcap_data = create_minimal_pcap_bytes(10)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("record_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        cid = response.json()["capture"]["id"]

        get_res = await client.get(f"/api/captures/{cid}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == cid
        assert get_res.json()["status"] == "UPLOADED"


@pytest.mark.asyncio
async def test_11_analysisjob_created_correctly():
    """11. AnalysisJob is created correctly."""
    pcap_data = create_minimal_pcap_bytes(11)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("job_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        jid = response.json()["job_id"]

        job_res = await client.get(f"/api/jobs/{jid}")
        assert job_res.status_code == 200
        assert job_res.json()["status"] == "PENDING"


@pytest.mark.asyncio
async def test_12_pcap_metadata_extracted_correctly(tmp_path):
    """12. PCAP metadata is extracted correctly."""
    pcap_bytes = create_minimal_pcap_bytes(12)
    temp_pcap = tmp_path / "sample.pcap"
    temp_pcap.write_bytes(pcap_bytes)

    meta = inspect_pcap_file(temp_pcap)
    assert meta.is_valid is True
    assert meta.total_packets == 2
    assert meta.detected_format == "pcap"
    assert meta.capture_start_time is not None
    assert meta.capture_end_time is not None


@pytest.mark.asyncio
async def test_13_corrupt_metadata_does_not_fabricate_values(tmp_path):
    """13. Missing/corrupt metadata does not produce fabricated values."""
    corrupt_file = tmp_path / "bad.pcap"
    corrupt_file.write_bytes(b"INVALID_HEADER_NON_PCAP")

    meta = inspect_pcap_file(corrupt_file)
    assert meta.is_valid is False
    assert meta.total_packets == 0
    assert meta.capture_start_time is None
    assert meta.capture_end_time is None


@pytest.mark.asyncio
async def test_14_get_capture_works():
    """14. GET capture works."""
    pcap_data = create_minimal_pcap_bytes(14)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("get_test.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        res = await client.post("/api/captures/upload", files=files)
        cid = res.json()["capture"]["id"]

        fetch_res = await client.get(f"/api/captures/{cid}")
        assert fetch_res.status_code == 200
        assert fetch_res.json()["filename"] == "get_test.pcap"


@pytest.mark.asyncio
async def test_15_get_captures_list_works():
    """15. GET captures works."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        list_res = await client.get("/api/captures")
        assert list_res.status_code == 200
        assert "items" in list_res.json()
        assert "total" in list_res.json()


@pytest.mark.asyncio
async def test_16_get_job_works():
    """16. GET job works."""
    pcap_data = create_minimal_pcap_bytes(16)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("job_get.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        res = await client.post("/api/captures/upload", files=files)
        jid = res.json()["job_id"]

        job_res = await client.get(f"/api/jobs/{jid}")
        assert job_res.status_code == 200
        assert job_res.json()["id"] == jid


@pytest.mark.asyncio
async def test_17_failed_upload_cleaned_up_safely():
    """17. Incomplete/failed upload is cleaned up safely."""
    tmp_upload_dir = Path(settings.upload_dir) / ".tmp"
    initial_tmp_files = set(tmp_upload_dir.glob("*.tmp")) if tmp_upload_dir.exists() else set()

    fake_pcap = b"INVALID_HEADER_DATA"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("fail_clean.pcap", io.BytesIO(fake_pcap), "application/octet-stream")}
        response = await client.post("/api/captures/upload", files=files)
        assert response.status_code == 400

    current_tmp_files = set(tmp_upload_dir.glob("*.tmp")) if tmp_upload_dir.exists() else set()
    assert current_tmp_files == initial_tmp_files

