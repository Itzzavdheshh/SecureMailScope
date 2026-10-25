"""
TCP Flow Identifier and Canonical 4-Tuple Manager.
Groups bidirectional TCP packets into single conversations.
Identifies client vs server endpoints using SYN initiation or mail port hints.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import dpkt

from app.analyzers.pcap_reader import PacketRecord


MAIL_PORTS = {25, 587, 465, 143, 993, 110, 995}


def make_canonical_key(ip1: str, port1: int, ip2: str, port2: int) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    """
    Create a canonical bidirectional 4-tuple key.
    Ensures (A, B) and (B, A) resolve to the exact same tuple.
    """
    ep1 = (ip1, port1)
    ep2 = (ip2, port2)
    return (ep1, ep2) if ep1 < ep2 else (ep2, ep1)


@dataclass
class TcpFlow:
    canonical_key: Tuple[Tuple[str, int], Tuple[str, int]]
    client_ip: str = ""
    client_port: int = 0
    server_ip: str = ""
    server_port: int = 0

    first_frame: int = 0
    last_frame: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    packet_count: int = 0
    bytes_transferred: int = 0

    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

    c2s_packets: List[PacketRecord] = field(default_factory=list)
    s2c_packets: List[PacketRecord] = field(default_factory=list)

    def add_packet(self, pkt: PacketRecord) -> None:
        """Add packet to flow, determining endpoint direction and updating metrics."""
        self.packet_count += 1
        self.bytes_transferred += len(pkt.payload)
        self.last_frame = pkt.frame_number
        self.end_time = pkt.timestamp

        if self.first_frame == 0:
            self.first_frame = pkt.frame_number
            self.start_time = pkt.timestamp

        # Check TCP flags (dpkt.tcp.TH_SYN, TH_ACK, TH_FIN, TH_RST)
        is_syn = bool(pkt.tcp_flags & dpkt.tcp.TH_SYN)
        is_ack = bool(pkt.tcp_flags & dpkt.tcp.TH_ACK)
        is_fin = bool(pkt.tcp_flags & dpkt.tcp.TH_FIN)
        is_rst = bool(pkt.tcp_flags & dpkt.tcp.TH_RST)

        if is_syn:
            self.syn_seen = True
        if is_fin:
            self.fin_seen = True
        if is_rst:
            self.rst_seen = True

        # Endpoint role assignment if not set
        if not self.client_ip:
            if is_syn and not is_ack:
                # SYN packet initiator is client
                self.client_ip, self.client_port = pkt.src_ip, pkt.src_port
                self.server_ip, self.server_port = pkt.dst_ip, pkt.dst_port
            elif pkt.dst_port in MAIL_PORTS:
                # Well-known mail port is server
                self.server_ip, self.server_port = pkt.dst_ip, pkt.dport if hasattr(pkt, 'dport') else pkt.dst_port
                self.client_ip, self.client_port = pkt.src_ip, pkt.src_port
            elif pkt.src_port in MAIL_PORTS:
                self.server_ip, self.server_port = pkt.src_ip, pkt.src_port
                self.client_ip, self.client_port = pkt.dst_ip, pkt.dst_port
            else:
                # Fallback: src is client
                self.client_ip, self.client_port = pkt.src_ip, pkt.src_port
                self.server_ip, self.server_port = pkt.dst_ip, pkt.dst_port

        # Sort into direction
        if pkt.src_ip == self.client_ip and pkt.src_port == self.client_port:
            self.c2s_packets.append(pkt)
        else:
            self.s2c_packets.append(pkt)


class TcpFlowManager:
    """Manages active TCP flow tables from streaming packet records."""

    def __init__(self):
        self.flows: Dict[Tuple[Tuple[str, int], Tuple[str, int]], TcpFlow] = {}

    def process_packet(self, pkt: PacketRecord) -> TcpFlow:
        key = make_canonical_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        if key not in self.flows:
            self.flows[key] = TcpFlow(canonical_key=key)

        flow = self.flows[key]
        flow.add_packet(pkt)
        return flow
