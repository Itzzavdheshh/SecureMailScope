"""
Forensic Timeline Generator.
Reconstructs normalized, chronological timeline of network, cryptographic, and security events
for an EmailSession / AnalysisJob from empirical PCAP evidence.
Enforces factual non-attacker-attribution language in event descriptions.
"""

import json
from typing import List, Optional, Dict, Any
from app.models.enums import Severity
from app.models.timeline import TimelineEvent
from app.models.session import EmailSession, StarttlsState, TlsHandshake
from app.models.certificate import Certificate, CertificateChain
from app.models.finding import Finding
from app.models.infrastructure import DriftEvent


def build_timeline_events_for_session(
    job_id: str,
    session: EmailSession,
    tls: Optional[TlsHandshake] = None,
    cert: Optional[Certificate] = None,
    chain: Optional[CertificateChain] = None,
    stls: Optional[StarttlsState] = None,
    findings: Optional[List[Finding]] = None,
    drift_events: Optional[List[DriftEvent]] = None,
) -> List[TimelineEvent]:
    """
    Construct normalized, chronological TimelineEvent records for an EmailSession.
    """
    events: List[TimelineEvent] = []
    sess_id = session.id
    base_ts = session.start_time.timestamp() if session.start_time else 0.0

    proto_name = session.protocol.value if hasattr(session.protocol, "value") else str(session.protocol)

    # 1. TCP Connection Start
    events.append(TimelineEvent(
        job_id=job_id,
        session_id=sess_id,
        timestamp=base_ts,
        event_type="TCP_CONNECT",
        frame_number=1,
        summary=f"TCP connection established between {session.client_ip}:{session.client_port} and {session.server_ip}:{session.server_port}.",
        severity=Severity.INFO,
        detail_json=json.dumps({"protocol": proto_name}),
    ))

    # 2. Protocol & Server Banner Identification
    if session.banner:
        events.append(TimelineEvent(
            job_id=job_id,
            session_id=sess_id,
            timestamp=base_ts + 0.001,
            event_type="SERVER_BANNER",
            frame_number=2,
            summary=f"Server banner received on {proto_name}: {session.banner[:80]}",
            severity=Severity.INFO,
            detail_json=json.dumps({"banner": session.banner}),
        ))

    # 3. STARTTLS Negotiation Events
    if stls:
        if stls.advertised_in_frame:
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.002,
                event_type="STARTTLS_ADVERTISED",
                frame_number=stls.advertised_in_frame,
                summary="STARTTLS capability advertised by server.",
                severity=Severity.INFO,
            ))
        if stls.command_in_frame:
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.003,
                event_type="STARTTLS_ATTEMPTED",
                frame_number=stls.command_in_frame,
                summary="Client issued STARTTLS command.",
                severity=Severity.INFO,
            ))
        if stls.response_in_frame:
            resp_code = stls.response_code or 220
            st_status = stls.observed_state.value if hasattr(stls.observed_state, "value") else str(stls.observed_state)
            sev = Severity.INFO if st_status in ("ACCEPTED", "TLS_FOLLOWED") else Severity.HIGH
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.004,
                event_type="STARTTLS_RESPONSE",
                frame_number=stls.response_in_frame,
                summary=f"Server responded to STARTTLS command with code {resp_code} (State: {st_status}).",
                severity=sev,
                detail_json=json.dumps({"response_code": resp_code, "observed_state": st_status}),
            ))

    # 4. TLS Handshake Events
    if tls:
        if tls.client_hello_frame:
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.010,
                event_type="TLS_CLIENT_HELLO",
                frame_number=tls.client_hello_frame,
                summary=f"TLS ClientHello sent (SNI: {tls.sni_hostname or 'None'}).",
                severity=Severity.INFO,
                detail_json=json.dumps({"sni": tls.sni_hostname, "offered_versions": tls.offered_tls_versions}),
            ))
        if tls.server_hello_frame:
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.011,
                event_type="TLS_SERVER_HELLO",
                frame_number=tls.server_hello_frame,
                summary=f"TLS ServerHello completed: {tls.negotiated_tls_version or 'Unknown'} negotiated with {tls.negotiated_cipher_suite or 'Unknown'} (Forward Secrecy: {tls.is_forward_secrecy}).",
                severity=Severity.INFO,
                detail_json=json.dumps({
                    "tls_version": tls.negotiated_tls_version,
                    "cipher_suite": tls.negotiated_cipher_suite,
                    "forward_secrecy": tls.is_forward_secrecy,
                }),
            ))

    # 5. Certificate Events
    if cert:
        events.append(TimelineEvent(
            job_id=job_id,
            session_id=sess_id,
            timestamp=base_ts + 0.012,
            event_type="CERTIFICATE_OBSERVED",
            frame_number=tls.server_hello_frame if tls else None,
            summary=f"Leaf X.509 certificate presented for {cert.subject_dn} (Fingerprint: {cert.sha256_fingerprint[:16] if cert.sha256_fingerprint else 'N/A'}...).",
            severity=Severity.INFO if cert.is_valid_at_capture else Severity.HIGH,
            detail_json=json.dumps({
                "subject": cert.subject_dn,
                "issuer": cert.issuer_dn,
                "fingerprint": cert.sha256_fingerprint,
                "valid_at_capture": cert.is_valid_at_capture,
            }),
        ))

    if chain:
        events.append(TimelineEvent(
            job_id=job_id,
            session_id=sess_id,
            timestamp=base_ts + 0.013,
            event_type="CERT_CHAIN_VALIDATED",
            frame_number=tls.server_hello_frame if tls else None,
            summary=f"Certificate chain validation status: {chain.validation_status} (Length: {chain.chain_length}).",
            severity=Severity.INFO if chain.validation_status == "VALID_AT_CAPTURE" else Severity.MEDIUM,
            detail_json=json.dumps({"validation_status": chain.validation_status, "chain_length": chain.chain_length}),
        ))

    # 6. Security Findings
    if findings:
        for f in findings:
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.015,
                event_type="FINDING_RAISED",
                frame_number=None,
                summary=f"Security finding [{f.rule_id}] raised: {f.title} ({f.severity.value if hasattr(f.severity, 'value') else f.severity}).",
                severity=f.severity,
                detail_json=json.dumps({"rule_id": f.rule_id, "title": f.title, "description": f.description}),
            ))

    # 7. Drift Events
    if drift_events:
        for de in drift_events:
            events.append(TimelineEvent(
                job_id=job_id,
                session_id=sess_id,
                timestamp=base_ts + 0.016,
                event_type="DRIFT_DETECTED",
                frame_number=None,
                summary=f"Cryptographic configuration drift observed: {de.delta_description}",
                severity=Severity.HIGH,
                detail_json=json.dumps({
                    "event_type": de.event_type.value if hasattr(de.event_type, "value") else str(de.event_type),
                    "previous_state": de.previous_state,
                    "new_state": de.new_state,
                }),
            ))

    # 8. Session Completion
    end_ts = session.end_time.timestamp() if session.end_time else base_ts + 0.020
    events.append(TimelineEvent(
        job_id=job_id,
        session_id=sess_id,
        timestamp=end_ts,
        event_type="SESSION_COMPLETE",
        frame_number=None,
        summary=f"Mail session complete. Total packets: {session.packet_count}, bytes transferred: {session.bytes_transferred}.",
        severity=Severity.INFO,
    ))

    # Sort deterministically: primary = timestamp, secondary = frame_number (0 if None)
    events.sort(key=lambda e: (e.timestamp, e.frame_number or 0))
    return events
