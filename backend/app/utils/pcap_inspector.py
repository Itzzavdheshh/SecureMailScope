"""
Lightweight PCAP/PCAPNG header inspector and metadata extractor.
Extracted metrics: packet count, first/last packet timestamps, link layer type, file format.
Does NOT perform protocol layer parsing, payload analysis, or cryptographic inspection.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import dpkt


# PCAP and PCAPNG Magic Byte Signatures (First 4 bytes)
MAGIC_PCAP_LE = b"\xa1\xb2\xc3\xd4"       # Microsecond Little-Endian
MAGIC_PCAP_BE = b"\xd4\xc3\xb2\xa1"       # Microsecond Big-Endian
MAGIC_PCAP_NANO_LE = b"\xa1\xb2\x3c\x4d"  # Nanosecond Little-Endian
MAGIC_PCAP_NANO_BE = b"\x4d\x3c\xb2\xa1"  # Nanosecond Big-Endian
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"        # PCAPNG Section Header Block (SHB)


@dataclass
class PcapMetadata:
    total_packets: int
    capture_start_time: Optional[datetime]
    capture_end_time: Optional[datetime]
    detected_format: str                    # "pcap" | "pcapng" | "unknown"
    link_type: Optional[int]
    is_valid: bool
    error_detail: Optional[str] = None


def detect_pcap_format(header_bytes: bytes) -> str:
    """Check magic bytes signature to determine file format."""
    if len(header_bytes) < 4:
        return "unknown"

    magic = header_bytes[:4]
    if magic in (MAGIC_PCAP_LE, MAGIC_PCAP_BE, MAGIC_PCAP_NANO_LE, MAGIC_PCAP_NANO_BE):
        return "pcap"
    elif magic == MAGIC_PCAPNG:
        return "pcapng"
    return "unknown"


def inspect_pcap_file(file_path: Path) -> PcapMetadata:
    """
    Extract lightweight packet count and capture timestamps from PCAP or PCAPNG file.
    Preserves exact capture timestamps without guessing missing values.
    """
    if not file_path.exists():
        return PcapMetadata(
            total_packets=0,
            capture_start_time=None,
            capture_end_time=None,
            detected_format="unknown",
            link_type=None,
            is_valid=False,
            error_detail="File not found",
        )

    with open(file_path, "rb") as f:
        header_bytes = f.read(4)

    fmt = detect_pcap_format(header_bytes)
    if fmt == "unknown":
        return PcapMetadata(
            total_packets=0,
            capture_start_time=None,
            capture_end_time=None,
            detected_format="unknown",
            link_type=None,
            is_valid=False,
            error_detail="Unrecognized PCAP magic bytes signature",
        )

    total_packets = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    link_type: Optional[int] = None

    try:
        with open(file_path, "rb") as f:
            if fmt == "pcap":
                try:
                    pcap_reader = dpkt.pcap.Reader(f)
                    link_type = pcap_reader.datalink()
                    for ts, pkt in pcap_reader:
                        total_packets += 1
                        if first_ts is None or ts < first_ts:
                            first_ts = ts
                        if last_ts is None or ts > last_ts:
                            last_ts = ts
                except Exception as e:
                    # Partial read if file truncated
                    pass
            elif fmt == "pcapng":
                try:
                    pcapng_reader = dpkt.pcapng.Reader(f)
                    for ts, pkt in pcapng_reader:
                        total_packets += 1
                        if first_ts is None or ts < first_ts:
                            first_ts = ts
                        if last_ts is None or ts > last_ts:
                            last_ts = ts
                except Exception as e:
                    # Partial read if file truncated
                    pass

        start_dt = (
            datetime.fromtimestamp(first_ts, tz=timezone.utc)
            if first_ts is not None and first_ts > 0
            else None
        )
        end_dt = (
            datetime.fromtimestamp(last_ts, tz=timezone.utc)
            if last_ts is not None and last_ts > 0
            else None
        )

        return PcapMetadata(
            total_packets=total_packets,
            capture_start_time=start_dt,
            capture_end_time=end_dt,
            detected_format=fmt,
            link_type=link_type,
            is_valid=True,
        )

    except Exception as exc:
        return PcapMetadata(
            total_packets=0,
            capture_start_time=None,
            capture_end_time=None,
            detected_format=fmt,
            link_type=None,
            is_valid=False,
            error_detail=str(exc),
        )
