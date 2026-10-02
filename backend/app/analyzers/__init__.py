"""
Analyzers package export module.
Exposes Phase 3 (TCP stream reassembly & protocol identification)
and Phase 4 (TLS record parsing, X.509 certificate analysis, STARTTLS state machine).
"""

from app.analyzers.pcap_reader import stream_pcap_frames, PacketRecord
from app.analyzers.tcp_flow import TcpFlowManager, TcpFlow, make_canonical_key
from app.analyzers.tcp_reassembler import reassemble_packet_list, ReassembledStream, StreamSegment
from app.analyzers.protocol_detector import classify_email_flow, ProtocolClassification
from app.analyzers.starttls_detector import detect_starttls_events, StarttlsDetectionResult
from app.analyzers.tls_parser import (
    parse_tls_records,
    parse_client_hello,
    parse_server_hello,
    parse_certificate_msg,
    ClientHelloParsed,
    ServerHelloParsed,
    TlsCertificateParsed,
    normalize_tls_version,
)
from app.analyzers.cert_analyzer import (
    parse_x509_certificate,
    analyze_certificate_chain,
    X509CertAnalysis,
    CertificateChainAnalysis,
)
from app.analyzers.identity import (
    construct_identity_key,
    build_cryptographic_profile,
    CryptographicProfile,
)
from app.analyzers.baseline import (
    InfrastructureBaseline,
    BaselineStatus,
    BaselineStore,
    global_baseline_store,
)
from app.analyzers.drift_detector import (
    compare_profiles_for_drift,
    DriftDetectionResult,
)
from app.analyzers.timeline_builder import build_timeline_events_for_session
from app.analyzers.pipeline import run_pipeline, run_phase3_pipeline

__all__ = [
    "stream_pcap_frames",
    "PacketRecord",
    "TcpFlowManager",
    "TcpFlow",
    "make_canonical_key",
    "reassemble_packet_list",
    "ReassembledStream",
    "StreamSegment",
    "classify_email_flow",
    "ProtocolClassification",
    "detect_starttls_events",
    "StarttlsDetectionResult",
    "parse_tls_records",
    "parse_client_hello",
    "parse_server_hello",
    "parse_certificate_msg",
    "ClientHelloParsed",
    "ServerHelloParsed",
    "TlsCertificateParsed",
    "normalize_tls_version",
    "parse_x509_certificate",
    "analyze_certificate_chain",
    "X509CertAnalysis",
    "CertificateChainAnalysis",
    "evaluate_starttls_state",
    "StarttlsStateEvaluation",
    "construct_identity_key",
    "build_cryptographic_profile",
    "CryptographicProfile",
    "InfrastructureBaseline",
    "BaselineStatus",
    "BaselineStore",
    "global_baseline_store",
    "compare_profiles_for_drift",
    "DriftDetectionResult",
    "build_timeline_events_for_session",
    "run_pipeline",
    "run_phase3_pipeline",
]

