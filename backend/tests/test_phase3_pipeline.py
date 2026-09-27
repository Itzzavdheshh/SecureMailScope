"""
Phase 3 TCP Stream Reconstruction & Email Session Identification Test Suite.
Verifies all 20 Phase 3 requirements: streaming PCAP reading, bidirectional TCP grouping,
sequence reassembly, fragmented banners/commands, protocol detection (SMTP/IMAP/POP3),
STARTTLS event tracking, retransmission/gap handling, frame evidence preservation,
and complete EmailSession database persistence.
"""

import io
import struct
import pytest
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.db.session import Base
from app.main import app
from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    StarttlsState,
    JobStatus,
    ProtocolType,
    StarttlsStatus,
    Confidence,
)

from app.analyzers.pcap_reader import stream_pcap_frames, PacketRecord
from app.analyzers.tcp_flow import TcpFlowManager, make_canonical_key
from app.analyzers.tcp_reassembler import reassemble_packet_list, StreamSegment
from app.analyzers.protocol_detector import classify_email_flow
from app.analyzers.starttls_detector import detect_starttls_events
from app.analyzers.pipeline import run_phase3_pipeline


def build_raw_pcap(packet_payloads: list) -> bytes:
    """
    Construct a valid in-memory PCAP file containing TCP packets.
    packet_payloads: list of dicts:
        {
          "src_ip": "192.168.1.10", "dst_ip": "198.51.100.25",
          "src_port": 54321, "dst_port": 25,
          "seq": 100, "ack": 1, "flags": 0x18 (PSH+ACK),
          "timestamp": 1700000000.1,
          "payload": b"220 mail.example.com ESMTP\r\n"
        }
    """
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet linktype
    pcap_data = bytearray(global_hdr)

    for p in packet_payloads:
        payload = p.get("payload", b"")
        src_ip_bytes = bytes(map(int, p.get("src_ip", "192.168.1.10").split(".")))
        dst_ip_bytes = bytes(map(int, p.get("dst_ip", "198.51.100.25").split(".")))
        src_port = p.get("src_port", 54321)
        dst_port = p.get("dst_port", 25)
        seq = p.get("seq", 100)
        ack = p.get("ack", 1)
        flags = p.get("flags", 0x18)
        ts = p.get("timestamp", 1700000000.0)

        # TCP Header (20 bytes)
        tcp_hdr = struct.pack(">HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | flags, 64240, 0, 0)
        tcp_len = len(tcp_hdr) + len(payload)

        # IP Header (20 bytes)
        ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + tcp_len, 1, 0, 64, 6, 0, src_ip_bytes, dst_ip_bytes)

        # Ethernet Header (14 bytes)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

        full_packet = eth_hdr + ip_hdr + tcp_hdr + payload
        pkt_len = len(full_packet)

        sec = int(ts)
        usec = int((ts - sec) * 1000000)
        pkt_hdr = struct.pack("<IIII", sec, usec, pkt_len, pkt_len)

        pcap_data.extend(pkt_hdr)
        pcap_data.extend(full_packet)

    return bytes(pcap_data)


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


@pytest.mark.asyncio
async def test_01_single_tcp_flow_reconstruction(tmp_path):
    """1. Single TCP flow reconstruction."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 12345, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"220 mail.com\r\n"}
    ])
    pcap_file = tmp_path / "single_flow.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    assert len(mgr.flows) == 1
    flow = list(mgr.flows.values())[0]
    assert flow.client_ip == "10.0.0.1"
    assert flow.server_ip == "10.0.0.2"


@pytest.mark.asyncio
async def test_02_bidirectional_flow_grouping(tmp_path):
    """2. Bidirectional flow grouping."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"EHLO client\r\n"},
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"250-STARTTLS\r\n"},
    ])
    pcap_file = tmp_path / "bidi_flow.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    assert len(mgr.flows) == 1
    flow = list(mgr.flows.values())[0]
    assert len(flow.c2s_packets) == 1
    assert len(flow.s2c_packets) == 1


@pytest.mark.asyncio
async def test_03_fragmented_smtp_banner(tmp_path):
    """3. Fragmented SMTP banner."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220 mail."},
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 10, "payload": b"example.com ESMTP\r\n"},
    ])
    pcap_file = tmp_path / "frag_banner.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    s2c = reassemble_packet_list(flow.s2c_packets, direction="s2c")
    assert s2c.text == "220 mail.example.com ESMTP\r\n"


@pytest.mark.asyncio
async def test_04_fragmented_smtp_command(tmp_path):
    """4. Fragmented SMTP command."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"START"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 6, "payload": b"TLS\r\n"},
    ])
    pcap_file = tmp_path / "frag_cmd.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, direction="c2s")
    assert c2s.text == "STARTTLS\r\n"


@pytest.mark.asyncio
async def test_05_smtp_detection(tmp_path):
    """5. SMTP detection."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220 mail.com ESMTP\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"EHLO client\r\n"},
    ])
    pcap_file = tmp_path / "smtp.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")
    cls = classify_email_flow(flow, c2s, s2c)

    assert cls.protocol == ProtocolType.SMTP
    assert cls.confidence == Confidence.HIGH


@pytest.mark.asyncio
async def test_06_imap_detection(tmp_path):
    """6. IMAP detection."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 143, "dst_ip": "10.0.0.1", "dst_port": 6000, "seq": 1, "payload": b"* OK IMAP4rev1 Service Ready\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 6000, "dst_ip": "10.0.0.2", "dst_port": 143, "seq": 1, "payload": b"A1 CAPABILITY\r\n"},
    ])
    pcap_file = tmp_path / "imap.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")
    cls = classify_email_flow(flow, c2s, s2c)

    assert cls.protocol == ProtocolType.IMAP
    assert cls.confidence == Confidence.HIGH


@pytest.mark.asyncio
async def test_07_pop3_detection(tmp_path):
    """7. POP3 detection."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 110, "dst_ip": "10.0.0.1", "dst_port": 7000, "seq": 1, "payload": b"+OK POP3 server ready\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 7000, "dst_ip": "10.0.0.2", "dst_port": 110, "seq": 1, "payload": b"CAPA\r\n"},
    ])
    pcap_file = tmp_path / "pop3.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")
    cls = classify_email_flow(flow, c2s, s2c)

    assert cls.protocol == ProtocolType.POP3
    assert cls.confidence == Confidence.HIGH


@pytest.mark.asyncio
async def test_08_port_hint_without_sufficient_evidence(tmp_path):
    """8. Port hint without sufficient protocol evidence yields LOW confidence."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 8000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"SOME_UNKNOWN_DATA"}
    ])
    pcap_file = tmp_path / "unknown_smtp.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")
    cls = classify_email_flow(flow, c2s, s2c)

    assert cls.protocol == ProtocolType.SMTP
    assert cls.confidence == Confidence.LOW


@pytest.mark.asyncio
async def test_09_implicit_tls_port_classification(tmp_path):
    """9. Implicit TLS port classification."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 993, "dst_ip": "10.0.0.1", "dst_port": 9000, "seq": 1, "payload": b"\x16\x03\x03\x00\x40"}
    ])
    pcap_file = tmp_path / "imaps.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")
    cls = classify_email_flow(flow, c2s, s2c)

    assert cls.is_tls_implicit is True
    assert cls.protocol == ProtocolType.IMAP


@pytest.mark.asyncio
async def test_10_starttls_command_detection(tmp_path):
    """10. STARTTLS command detection."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220-mail.com ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": "STARTTLS\r\n".encode()},
    ])
    pcap_file = tmp_path / "starttls_cmd.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")

    st_res = detect_starttls_events(ProtocolType.SMTP, c2s, s2c)
    assert st_res.status == StarttlsStatus.ATTEMPTED
    assert st_res.command_frame is not None


@pytest.mark.asyncio
async def test_11_starttls_acceptance_detection(tmp_path):
    """11. STARTTLS acceptance detection."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220-mail.com ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 35, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
    ])
    pcap_file = tmp_path / "starttls_accept.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")

    st_res = detect_starttls_events(ProtocolType.SMTP, c2s, s2c)
    assert st_res.status == StarttlsStatus.ACCEPTED
    assert st_res.response_code == 220


@pytest.mark.asyncio
async def test_12_starttls_rejection_detection(tmp_path):
    """12. STARTTLS rejection detection."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220-mail.com ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 35, "payload": b"454 TLS not available\r\n"},
    ])

    pcap_file = tmp_path / "starttls_reject.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")

    st_res = detect_starttls_events(ProtocolType.SMTP, c2s, s2c)
    assert st_res.status == StarttlsStatus.REJECTED
    assert st_res.response_code == 454


@pytest.mark.asyncio
async def test_13_tcp_retransmission_handling():
    """13. TCP retransmission handling."""
    pkts = [
        PacketRecord(1, 100.0, "10.0.0.1", 5000, "10.0.0.2", 25, 0x18, 1, 1, b"EHLO client\r\n"),
        PacketRecord(2, 101.0, "10.0.0.1", 5000, "10.0.0.2", 25, 0x18, 1, 1, b"EHLO client\r\n"),  # Duplicate seq=1
    ]
    stream = reassemble_packet_list(pkts, "c2s")
    assert stream.has_retransmissions is True
    assert stream.text == "EHLO client\r\n"


@pytest.mark.asyncio
async def test_14_tcp_sequence_gap_handling():
    """14. TCP sequence gap handling."""
    pkts = [
        PacketRecord(1, 100.0, "10.0.0.1", 5000, "10.0.0.2", 25, 0x18, 1, 1, b"EHLO "),
        PacketRecord(3, 102.0, "10.0.0.1", 5000, "10.0.0.2", 25, 0x18, 50, 1, b"client\r\n"),  # Gap: seq jumped from 6 to 50
    ]
    stream = reassemble_packet_list(pkts, "c2s")
    assert stream.has_gaps is True
    assert "EHLO client\r\n" in stream.text


@pytest.mark.asyncio
async def test_15_frame_number_preservation(tmp_path):
    """15. Frame number preservation."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"STARTTLS\r\n"}
    ])
    pcap_file = tmp_path / "frame_preservation.pcap"
    pcap_file.write_bytes(pcap_data)

    records = list(stream_pcap_frames(pcap_file))
    assert len(records) == 1
    assert records[0].frame_number == 1


@pytest.mark.asyncio
async def test_16_timestamp_preservation(tmp_path):
    """16. Timestamp preservation."""
    ts_expected = 1700000000.123456
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "timestamp": ts_expected, "payload": b"EHLO"}
    ])
    pcap_file = tmp_path / "ts_preservation.pcap"
    pcap_file.write_bytes(pcap_data)

    records = list(stream_pcap_frames(pcap_file))
    assert len(records) == 1
    assert abs(records[0].timestamp - ts_expected) < 0.001


@pytest.mark.asyncio
async def test_17_evidence_mapping_from_reconstructed_data(tmp_path):
    """17. Evidence mapping from reconstructed data to original frames."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.2", "src_port": 25, "dst_ip": "10.0.0.1", "dst_port": 5000, "seq": 1, "payload": b"220-mail.com ESMTP\r\n250-STARTTLS\r\n"},
    ])
    pcap_file = tmp_path / "evidence_map.pcap"
    pcap_file.write_bytes(pcap_data)

    mgr = TcpFlowManager()
    for pkt in stream_pcap_frames(pcap_file):
        mgr.process_packet(pkt)

    flow = list(mgr.flows.values())[0]
    c2s = reassemble_packet_list(flow.c2s_packets, "c2s")
    s2c = reassemble_packet_list(flow.s2c_packets, "s2c")
    cls = classify_email_flow(flow, c2s, s2c)

    assert len(cls.evidence_list) >= 1
    assert "frame_number" in cls.evidence_list[0]
    assert cls.evidence_list[0]["frame_number"] == 1


@pytest.mark.asyncio
async def test_18_emailsession_database_persistence(tmp_path):
    """18. EmailSession database persistence."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"220 mail.com\r\n"}
    ])
    pcap_file = tmp_path / "db_persist.pcap"
    pcap_file.write_bytes(pcap_data)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        # Upload
        files = {"file": ("db_persist.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        up_res = await client.post("/api/captures/upload", files=files)
        assert up_res.status_code == 201
        job_id = up_res.json()["job_id"]

        # Trigger Phase 3 analysis
        start_res = await client.post(f"/api/jobs/{job_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["job"]["status"] == "COMPLETED"
        assert start_res.json()["job"]["total_sessions"] == 1


@pytest.mark.asyncio
async def test_19_successful_analysisjob_completion(tmp_path):
    """19. Successful AnalysisJob completion."""
    pcap_data = build_raw_pcap([
        {"src_ip": "10.0.0.1", "src_port": 5000, "dst_ip": "10.0.0.2", "dst_port": 25, "seq": 1, "payload": b"220 mail.com\r\n"}
    ])
    pcap_file = tmp_path / "job_completion.pcap"
    pcap_file.write_bytes(pcap_data)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        files = {"file": ("job_completion.pcap", io.BytesIO(pcap_data), "application/octet-stream")}
        up_res = await client.post("/api/captures/upload", files=files)
        job_id = up_res.json()["job_id"]

        await client.post(f"/api/jobs/{job_id}/start")

        job_get = await client.get(f"/api/jobs/{job_id}")
        assert job_get.status_code == 200
        assert job_get.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_20_malformed_packet_handling_without_crashing(tmp_path):
    """20. Malformed packet handling without crashing the whole analysis."""
    # Truncated / corrupt packet header followed by valid packet
    corrupt_data = b"\xa1\xb2\xc3\xd4\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00" + b"\xff" * 20
    pcap_file = tmp_path / "malformed.pcap"
    pcap_file.write_bytes(corrupt_data)

    # Streaming should catch error without crashing
    packets = list(stream_pcap_frames(pcap_file))
    assert isinstance(packets, list)
