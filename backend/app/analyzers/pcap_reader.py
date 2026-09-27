"""
Streaming PCAP / PCAPNG packet frame reader using dpkt.
Streams frame-by-frame (never loading entire file into memory).
Preserves 1-indexed frame numbers, epoch timestamps, 4-tuple IP/ports, TCP flags, sequence numbers, and payloads.
"""

import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Optional
import dpkt

from app.utils.pcap_inspector import detect_pcap_format


@dataclass
class PacketRecord:
    frame_number: int             # 1-indexed frame number
    timestamp: float              # Microsecond precision epoch float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    tcp_flags: int
    seq_num: int
    ack_num: int
    payload: bytes
    capture_id: str = ""


def _ip_to_str(ip_bytes: bytes) -> str:
    """Convert raw IP bytes (v4 or v6) to readable string."""
    try:
        if len(ip_bytes) == 4:
            return socket.inet_ntop(socket.AF_INET, ip_bytes)
        elif len(ip_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    except Exception:
        pass
    return "0.0.0.0"


def stream_pcap_frames(
    file_path: Path, capture_id: str = ""
) -> Generator[PacketRecord, None, None]:
    """
    Stream PCAP/PCAPNG packet frames line-by-line using dpkt.
    Handles malformed or non-TCP packets gracefully without crashing the pipeline.
    """
    if not file_path.exists():
        return

    with open(file_path, "rb") as f:
        header_bytes = f.read(16)

    fmt = detect_pcap_format(header_bytes)
    if fmt == "unknown":
        return

    frame_number = 0

    with open(file_path, "rb") as f:
        reader = None
        if fmt == "pcap":
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception:
                return
        elif fmt == "pcapng":
            try:
                reader = dpkt.pcapng.Reader(f)
            except Exception:
                return

        if reader is None:
            return

        for ts, pkt in reader:
            frame_number += 1

            try:
                # Dissect Ethernet / Link layer
                try:
                    eth = dpkt.ethernet.Ethernet(pkt)
                except Exception:
                    # Raw IP fallback if no ethernet header
                    eth = pkt

                ip_obj = None
                if isinstance(eth, dpkt.ethernet.Ethernet):
                    if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        ip_obj = eth.data
                elif isinstance(eth, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    ip_obj = eth

                if ip_obj is None or not hasattr(ip_obj, "data"):
                    continue

                tcp_obj = ip_obj.data
                if not isinstance(tcp_obj, dpkt.tcp.TCP):
                    continue

                src_ip = _ip_to_str(ip_obj.src)
                dst_ip = _ip_to_str(ip_obj.dst)
                src_port = int(tcp_obj.sport)
                dst_port = int(tcp_obj.dport)
                flags = int(tcp_obj.flags)
                seq = int(tcp_obj.seq)
                ack = int(tcp_obj.ack)
                payload = bytes(tcp_obj.data)

                yield PacketRecord(
                    frame_number=frame_number,
                    timestamp=float(ts),
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    tcp_flags=flags,
                    seq_num=seq,
                    ack_num=ack,
                    payload=payload,
                    capture_id=capture_id,
                )

            except Exception:
                # Malformed frame protection: continue reading next packet
                continue
