"""
STARTTLS Event Detector.
Scans reconstructed application streams for STARTTLS advertisement, command submission,
and server acceptance/rejection events.
Maps events into explicit StarttlsStatus states with low-level frame evidence.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from app.models.enums import ProtocolType, StarttlsStatus
from app.analyzers.tcp_reassembler import ReassembledStream, StreamSegment


@dataclass
class StarttlsEvent:
    event_type: str                     # "STARTTLS_ADVERTISED", "STARTTLS_COMMAND", "STARTTLS_ACCEPTED", "STARTTLS_REJECTED"
    frame_number: int
    timestamp: float
    direction: str                     # "c2s" | "s2c"
    observed_text: str
    response_code: Optional[int] = None


@dataclass
class StarttlsDetectionResult:
    status: StarttlsStatus
    advertised_frame: Optional[int] = None
    command_frame: Optional[int] = None
    response_frame: Optional[int] = None
    response_code: Optional[int] = None
    is_downgrade_suspected: bool = False
    events: List[StarttlsEvent] = field(default_factory=list)


def detect_starttls_events(
    protocol: ProtocolType,
    c2s_stream: ReassembledStream,
    s2c_stream: ReassembledStream,
) -> StarttlsDetectionResult:
    """
    Detect STARTTLS protocol negotiation events across Client and Server streams.
    Returns structured StarttlsDetectionResult with low-level evidence events.
    """
    events: List[StarttlsEvent] = []
    adv_frame: Optional[int] = None
    cmd_frame: Optional[int] = None
    resp_frame: Optional[int] = None
    resp_code: Optional[int] = None

    if protocol == ProtocolType.UNKNOWN:
        return StarttlsDetectionResult(status=StarttlsStatus.NOT_OBSERVED)

    # ─── 1. Check Advertisement (Server Stream s2c) ─────────────────────────
    for seg in s2c_stream.segments:
        text_upper = seg.payload.decode("utf-8", errors="ignore").upper()
        if "STARTTLS" in text_upper or "STLS" in text_upper:
            adv_frame = seg.frame_number
            events.append(
                StarttlsEvent(
                    event_type="STARTTLS_ADVERTISED",
                    frame_number=seg.frame_number,
                    timestamp=seg.timestamp,
                    direction="s2c",
                    observed_text=seg.payload.decode("utf-8", errors="ignore").strip(),
                )
            )
            break

    # ─── 2. Check Command (Client Stream c2s) ────────────────────────────────
    for seg in c2s_stream.segments:
        text_upper = seg.payload.decode("utf-8", errors="ignore").upper()
        if "STARTTLS" in text_upper or text_upper.strip() == "STLS":
            cmd_frame = seg.frame_number
            events.append(
                StarttlsEvent(
                    event_type="STARTTLS_COMMAND",
                    frame_number=seg.frame_number,
                    timestamp=seg.timestamp,
                    direction="c2s",
                    observed_text=seg.payload.decode("utf-8", errors="ignore").strip(),
                )
            )
            break

    # ─── 3. Check Server Response (Server Stream s2c after Command) ──────────
    if cmd_frame is not None:
        for seg in s2c_stream.segments:
            if seg.frame_number > cmd_frame:
                text_clean = seg.payload.decode("utf-8", errors="ignore").strip()
                text_upper = text_clean.upper()

                # SMTP acceptance: "220 ..."
                if protocol == ProtocolType.SMTP:
                    if text_upper.startswith("220"):
                        resp_frame = seg.frame_number
                        resp_code = 220
                        events.append(
                            StarttlsEvent(
                                event_type="STARTTLS_ACCEPTED",
                                frame_number=seg.frame_number,
                                timestamp=seg.timestamp,
                                direction="s2c",
                                observed_text=text_clean,
                                response_code=220,
                            )
                        )
                        break
                    elif any(text_upper.startswith(code) for code in ("454", "501", "503", "554")):
                        resp_frame = seg.frame_number
                        try:
                            resp_code = int(text_upper[:3])
                        except ValueError:
                            resp_code = 500
                        events.append(
                            StarttlsEvent(
                                event_type="STARTTLS_REJECTED",
                                frame_number=seg.frame_number,
                                timestamp=seg.timestamp,
                                direction="s2c",
                                observed_text=text_clean,
                                response_code=resp_code,
                            )
                        )
                        break

                # IMAP acceptance: "A001 OK ..."
                elif protocol == ProtocolType.IMAP:
                    if "OK" in text_upper:
                        resp_frame = seg.frame_number
                        resp_code = 200
                        events.append(
                            StarttlsEvent(
                                event_type="STARTTLS_ACCEPTED",
                                frame_number=seg.frame_number,
                                timestamp=seg.timestamp,
                                direction="s2c",
                                observed_text=text_clean,
                                response_code=200,
                            )
                        )
                        break
                    elif "NO" in text_upper or "BAD" in text_upper:
                        resp_frame = seg.frame_number
                        resp_code = 500
                        events.append(
                            StarttlsEvent(
                                event_type="STARTTLS_REJECTED",
                                frame_number=seg.frame_number,
                                timestamp=seg.timestamp,
                                direction="s2c",
                                observed_text=text_clean,
                                response_code=500,
                            )
                        )
                        break

                # POP3 acceptance: "+OK ..."
                elif protocol == ProtocolType.POP3:
                    if text_upper.startswith("+OK"):
                        resp_frame = seg.frame_number
                        resp_code = 200
                        events.append(
                            StarttlsEvent(
                                event_type="STARTTLS_ACCEPTED",
                                frame_number=seg.frame_number,
                                timestamp=seg.timestamp,
                                direction="s2c",
                                observed_text=text_clean,
                                response_code=200,
                            )
                        )
                        break
                    elif text_upper.startswith("-ERR"):
                        resp_frame = seg.frame_number
                        resp_code = 500
                        events.append(
                            StarttlsEvent(
                                event_type="STARTTLS_REJECTED",
                                frame_number=seg.frame_number,
                                timestamp=seg.timestamp,
                                direction="s2c",
                                observed_text=text_clean,
                                response_code=500,
                            )
                        )
                        break

    # Determine final StarttlsStatus
    final_status = StarttlsStatus.NOT_OBSERVED

    if any(e.event_type == "STARTTLS_ACCEPTED" for e in events):
        final_status = StarttlsStatus.ACCEPTED
    elif any(e.event_type == "STARTTLS_REJECTED" for e in events):
        final_status = StarttlsStatus.REJECTED
    elif cmd_frame is not None:
        final_status = StarttlsStatus.ATTEMPTED
    elif adv_frame is not None:
        final_status = StarttlsStatus.ADVERTISED

    return StarttlsDetectionResult(
        status=final_status,
        advertised_frame=adv_frame,
        command_frame=cmd_frame,
        response_frame=resp_frame,
        response_code=resp_code,
        events=events,
    )
