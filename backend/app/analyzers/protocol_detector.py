"""
Email Protocol Inspector & Classifier.
Detects SMTP, IMAP, POP3, and Implicit TLS by combining port hints, server banners,
and application command/response patterns.
Preserves evidence records linking classifications directly back to packet frame numbers.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import re

from app.models.enums import Confidence, ProtocolType, StarttlsStatus
from app.analyzers.tcp_flow import TcpFlow
from app.analyzers.tcp_reassembler import ReassembledStream, StreamSegment


# Port hints
SMTP_PORTS = {25, 587, 465}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}
IMPLICIT_TLS_PORTS = {465, 993, 995}


@dataclass
class ProtocolClassification:
    protocol: ProtocolType
    confidence: Confidence
    is_tls_implicit: bool
    banner: Optional[str]
    starttls_status: StarttlsStatus
    evidence_list: List[dict] = field(default_factory=list)


def is_tls_record_header(data: bytes) -> bool:
    """Check if stream bytes begin with a TLS Record ContentType 0x16 (Handshake)."""
    if len(data) >= 5:
        content_type = data[0]
        major = data[1]
        minor = data[2]
        if content_type == 0x16 and major == 3 and minor in (0, 1, 2, 3, 4):
            return True
    return False


def classify_email_flow(
    flow: TcpFlow, c2s_stream: ReassembledStream, s2c_stream: ReassembledStream
) -> ProtocolClassification:
    """
    Classify a TCP flow into SMTP, IMAP, POP3, or UNKNOWN.
    Evaluates server stream (s2c) for banners, client stream (c2s) for commands, and port hints.
    """
    server_port = flow.server_port
    s2c_text = s2c_stream.text.upper()
    c2s_text = c2s_stream.text.upper()
    s2c_data = s2c_stream.data

    evidence_list: List[dict] = []
    banner_text: Optional[str] = None

    # Check for Implicit TLS header or port
    is_implicit_tls = False
    if server_port in IMPLICIT_TLS_PORTS or is_tls_record_header(s2c_data):
        is_implicit_tls = True
        if s2c_stream.segments:
            first_seg = s2c_stream.segments[0]
            evidence_list.append({
                "frame_number": first_seg.frame_number,
                "packet_timestamp": first_seg.timestamp,
                "protocol_layer": "TLS",
                "field_name": "implicit_tls_handshake",
                "observed_value": f"Implicit TLS detected on server port {server_port}",
            })

    # Extract first line of server response for banner
    if s2c_stream.text.strip():
        banner_line = s2c_stream.text.strip().split("\r\n")[0].split("\n")[0]
        if len(banner_line) > 0 and len(banner_line) < 512:
            banner_text = banner_line

    # ─── 1. SMTP Detection ──────────────────────────────────────────────────
    smtp_score = 0
    if server_port in SMTP_PORTS:
        smtp_score += 1

    if s2c_text.startswith("220") or "ESMTP" in s2c_text or "SMTP" in s2c_text:
        smtp_score += 3
        if s2c_stream.segments:
            evidence_list.append({
                "frame_number": s2c_stream.segments[0].frame_number,
                "packet_timestamp": s2c_stream.segments[0].timestamp,
                "protocol_layer": "SMTP",
                "field_name": "server_banner",
                "observed_value": banner_text or "220 ESMTP Banner",
            })

    smtp_commands = ["EHLO", "HELO", "MAIL FROM:", "RCPT TO:", "STARTTLS"]
    for cmd in smtp_commands:
        if cmd in c2s_text:
            smtp_score += 2
            # Find matching segment
            for seg in c2s_stream.segments:
                if cmd.encode() in seg.payload.upper():
                    evidence_list.append({
                        "frame_number": seg.frame_number,
                        "packet_timestamp": seg.timestamp,
                        "protocol_layer": "SMTP",
                        "field_name": "client_command",
                        "observed_value": cmd,
                    })
                    break

    # ─── 2. IMAP Detection ──────────────────────────────────────────────────
    imap_score = 0
    if server_port in IMAP_PORTS:
        imap_score += 1

    if s2c_text.startswith("* OK") or "IMAP4" in s2c_text:
        imap_score += 3
        if s2c_stream.segments:
            evidence_list.append({
                "frame_number": s2c_stream.segments[0].frame_number,
                "packet_timestamp": s2c_stream.segments[0].timestamp,
                "protocol_layer": "IMAP",
                "field_name": "server_banner",
                "observed_value": banner_text or "* OK IMAP4",
            })

    imap_commands = ["CAPABILITY", "LOGIN", "AUTHENTICATE", "STARTTLS"]
    for cmd in imap_commands:
        if cmd in c2s_text:
            imap_score += 2
            for seg in c2s_stream.segments:
                if cmd.encode() in seg.payload.upper():
                    evidence_list.append({
                        "frame_number": seg.frame_number,
                        "packet_timestamp": seg.timestamp,
                        "protocol_layer": "IMAP",
                        "field_name": "client_command",
                        "observed_value": cmd,
                    })
                    break

    # ─── 3. POP3 Detection ──────────────────────────────────────────────────
    pop3_score = 0
    if server_port in POP3_PORTS:
        pop3_score += 1

    if s2c_text.startswith("+OK") or "POP3" in s2c_text:
        pop3_score += 3
        if s2c_stream.segments:
            evidence_list.append({
                "frame_number": s2c_stream.segments[0].frame_number,
                "packet_timestamp": s2c_stream.segments[0].timestamp,
                "protocol_layer": "POP3",
                "field_name": "server_banner",
                "observed_value": banner_text or "+OK POP3",
            })

    pop3_commands = ["USER", "PASS", "CAPA", "STLS"]
    for cmd in pop3_commands:
        if cmd in c2s_text:
            pop3_score += 2
            for seg in c2s_stream.segments:
                if cmd.encode() in seg.payload.upper():
                    evidence_list.append({
                        "frame_number": seg.frame_number,
                        "packet_timestamp": seg.timestamp,
                        "protocol_layer": "POP3",
                        "field_name": "client_command",
                        "observed_value": cmd,
                    })
                    break

    # ─── Decision Logic ──────────────────────────────────────────────────────
    protocol = ProtocolType.UNKNOWN
    confidence = Confidence.LOW

    if smtp_score >= 3 or (smtp_score >= 1 and server_port in SMTP_PORTS and is_implicit_tls):
        protocol = ProtocolType.SMTP
        confidence = Confidence.HIGH if smtp_score >= 3 else Confidence.MEDIUM
    elif imap_score >= 3 or (imap_score >= 1 and server_port in IMAP_PORTS and is_implicit_tls):
        protocol = ProtocolType.IMAP
        confidence = Confidence.HIGH if imap_score >= 3 else Confidence.MEDIUM
    elif pop3_score >= 3 or (pop3_score >= 1 and server_port in POP3_PORTS and is_implicit_tls):
        protocol = ProtocolType.POP3
        confidence = Confidence.HIGH if pop3_score >= 3 else Confidence.MEDIUM
    elif server_port in SMTP_PORTS:
        protocol = ProtocolType.SMTP
        confidence = Confidence.LOW
    elif server_port in IMAP_PORTS:
        protocol = ProtocolType.IMAP
        confidence = Confidence.LOW
    elif server_port in POP3_PORTS:
        protocol = ProtocolType.POP3
        confidence = Confidence.LOW

    return ProtocolClassification(
        protocol=protocol,
        confidence=confidence,
        is_tls_implicit=is_implicit_tls,
        banner=banner_text,
        starttls_status=StarttlsStatus.NOT_OBSERVED,
        evidence_list=evidence_list,
    )
