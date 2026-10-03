"""
TCP Stream Reassembler.
Reconstructs application payload bytes in sequence order.
Preserves segment evidence mapping (frame_number, timestamp, seq_num, offset, payload).
Handles out-of-order segments, retransmissions, duplicate bytes, and sequence gaps without fabricating data.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from app.analyzers.pcap_reader import PacketRecord


@dataclass
class StreamSegment:
    frame_number: int
    timestamp: float
    seq_num: int
    direction: str                     # "c2s" | "s2c"
    payload: bytes
    offset_in_stream: int = 0


@dataclass
class ReassembledStream:
    direction: str                     # "c2s" | "s2c"
    data: bytes                        # Full concatenated reassembled payload bytes
    segments: List[StreamSegment]      # Preserved segment evidence list
    has_gaps: bool = False
    has_retransmissions: bool = False

    @property
    def text(self) -> str:
        """Decode stream bytes as ASCII/UTF-8 string (ignoring binary decode errors)."""
        return self.data.decode("utf-8", errors="replace")


def reassemble_packet_list(
    packets: List[PacketRecord], direction: str
) -> ReassembledStream:
    """
    Reassemble a list of PacketRecords for a single direction.
    Sorts by sequence number, handles duplicates/retransmissions, and tracks sequence gaps.
    """
    payload_packets = [p for p in packets if len(p.payload) > 0]
    if not payload_packets:
        return ReassembledStream(direction=direction, data=b"", segments=[])

    # Sort packets by TCP sequence number, then frame number
    sorted_packets = sorted(payload_packets, key=lambda p: (p.seq_num, p.frame_number))

    segments: List[StreamSegment] = []
    stream_bytes = bytearray()
    has_gaps = False
    has_retransmissions = False

    last_end_seq: Optional[int] = None
    current_stream_offset = 0

    for pkt in sorted_packets:
        seq = pkt.seq_num
        payload = pkt.payload
        pkt_len = len(payload)
        expected_next_seq = seq + pkt_len

        if last_end_seq is None:
            # First payload segment
            stream_bytes.extend(payload)
            segments.append(
                StreamSegment(
                    frame_number=pkt.frame_number,
                    timestamp=pkt.timestamp,
                    seq_num=seq,
                    direction=direction,
                    payload=payload,
                    offset_in_stream=0,
                )
            )
            current_stream_offset += pkt_len
            last_end_seq = expected_next_seq

        elif seq == last_end_seq:
            # In-sequence segment
            stream_bytes.extend(payload)
            segments.append(
                StreamSegment(
                    frame_number=pkt.frame_number,
                    timestamp=pkt.timestamp,
                    seq_num=seq,
                    direction=direction,
                    payload=payload,
                    offset_in_stream=current_stream_offset,
                )
            )
            current_stream_offset += pkt_len
            last_end_seq = expected_next_seq

        elif seq < last_end_seq:
            # Retransmission or overlap
            has_retransmissions = True
            overlap = last_end_seq - seq
            if overlap < pkt_len:
                # Partial new data in retransmitted segment
                new_payload = payload[overlap:]
                new_len = len(new_payload)
                stream_bytes.extend(new_payload)
                segments.append(
                    StreamSegment(
                        frame_number=pkt.frame_number,
                        timestamp=pkt.timestamp,
                        seq_num=seq + overlap,
                        direction=direction,
                        payload=new_payload,
                        offset_in_stream=current_stream_offset,
                    )
                )
                current_stream_offset += new_len
                last_end_seq = last_end_seq + new_len
            # If overlap >= pkt_len, complete duplicate: skip adding to stream

        elif seq > last_end_seq:
            # Sequence gap detected (missing packet segment)
            has_gaps = True
            # We do NOT fabricate dummy bytes; append available payload and log gap
            stream_bytes.extend(payload)
            segments.append(
                StreamSegment(
                    frame_number=pkt.frame_number,
                    timestamp=pkt.timestamp,
                    seq_num=seq,
                    direction=direction,
                    payload=payload,
                    offset_in_stream=current_stream_offset,
                )
            )
            current_stream_offset += pkt_len
            last_end_seq = expected_next_seq

    return ReassembledStream(
        direction=direction,
        data=bytes(stream_bytes),
        segments=segments,
        has_gaps=has_gaps,
        has_retransmissions=has_retransmissions,
    )
