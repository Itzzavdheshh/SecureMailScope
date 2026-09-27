"""
Pipeline Orchestrator for Phase 3, Phase 4, & Phase 5.
Executes PCAP frame streaming, TCP flow grouping, stream reassembly,
email protocol detection (SMTP/IMAP/POP3), STARTTLS negotiation tracking,
TLS record layer parsing, ClientHello/ServerHello parameter extraction,
JA3/JA3S fingerprinting, X.509 certificate parsing, rule engine evaluation,
transparent risk score calculation, and DB persistence.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    StarttlsState,
    TlsHandshake,
    Certificate,
    CertificateChain,
    Finding,
    Evidence,
    JobStatus,
    StarttlsStatus,
)

from app.analyzers.pcap_reader import stream_pcap_frames, PacketRecord
from app.analyzers.tcp_flow import TcpFlowManager
from app.analyzers.tcp_reassembler import reassemble_packet_list
from app.analyzers.protocol_detector import classify_email_flow
from app.analyzers.starttls_detector import detect_starttls_events
from app.analyzers.tls_parser import (
    parse_tls_records,
    parse_client_hello,
    parse_server_hello,
    parse_certificate_msg,
    ClientHelloParsed,
    ServerHelloParsed,
    TlsCertificateParsed,
)
from app.analyzers.cert_analyzer import analyze_certificate_chain
from app.analyzers.starttls_state_machine import evaluate_starttls_state
from app.rules import (
    load_rules_from_directory,
    load_risk_weights_config,
    evaluate_rules_for_session,
    calculate_session_risk_score,
    calculate_job_risk_score,
)

log = structlog.get_logger(__name__)


async def run_phase3_pipeline(
    capture: Capture, job: AnalysisJob, db: AsyncSession
) -> List[EmailSession]:
    """Alias for complete pipeline execution."""
    return await run_pipeline(capture, job, db)


async def run_pipeline(
    capture: Capture, job: AnalysisJob, db: AsyncSession
) -> List[EmailSession]:
    """
    Run complete PCAP analysis pipeline through Phase 5.

    Updates AnalysisJob status from PENDING -> RUNNING -> COMPLETED (or FAILED on error).
    Evaluates security rules, generates findings/evidence, and computes risk scores.
    """
    pcap_path = Path(capture.file_path)
    if not pcap_path.exists():
        job.status = JobStatus.FAILED
        job.error_message = f"Capture file not found at path '{capture.file_path}'"
        await db.commit()
        return []

    job.status = JobStatus.RUNNING
    job.started_at = datetime.now(timezone.utc)
    await db.commit()

    try:
        # Load Rule Definitions and Risk Weights Configuration
        active_rules = load_rules_from_directory()
        risk_config = load_risk_weights_config()

        # Step 1: Stream frames from PCAP
        flow_manager = TcpFlowManager()
        for pkt in stream_pcap_frames(pcap_path, capture_id=capture.id):
            flow_manager.process_packet(pkt)

        created_sessions: List[EmailSession] = []
        session_risk_scores: List[float] = []
        session_index = 0

        # Step 2: Iterate TCP flows and process each conversation
        for key, flow in flow_manager.flows.items():
            session_index += 1
            c2s_stream = reassemble_packet_list(flow.c2s_packets, direction="c2s")
            s2c_stream = reassemble_packet_list(flow.s2c_packets, direction="s2c")

            # Step 3: Classify email protocol
            classification = classify_email_flow(flow, c2s_stream, s2c_stream)

            # Step 4: Initial STARTTLS event detection
            starttls_res = detect_starttls_events(
                classification.protocol, c2s_stream, s2c_stream
            )

            # Step 5: TLS Handshake & Certificate Extraction across flow packets
            client_hello: Optional[ClientHelloParsed] = None
            server_hello: Optional[ServerHelloParsed] = None
            cert_msg: Optional[TlsCertificateParsed] = None

            all_flow_packets = sorted(
                flow.c2s_packets + flow.s2c_packets, key=lambda p: p.frame_number
            )

            for pkt in all_flow_packets:
                if not pkt.payload:
                    continue
                records = parse_tls_records(pkt.payload, pkt.frame_number, pkt.timestamp)
                for rec in records:
                    if rec.content_type == 22:  # Handshake record
                        if not client_hello:
                            ch_try = parse_client_hello(rec.payload, rec.frame_number, rec.timestamp)
                            if ch_try:
                                client_hello = ch_try

                        if not server_hello:
                            sh_try = parse_server_hello(rec.payload, rec.frame_number, rec.timestamp)
                            if sh_try:
                                server_hello = sh_try

                        if not cert_msg:
                            cm_try = parse_certificate_msg(rec.payload, rec.frame_number, rec.timestamp)
                            if cm_try:
                                cert_msg = cm_try

            tls_observed = (client_hello is not None or server_hello is not None)

            # Step 6: Evaluate Complete STARTTLS State Machine
            st_eval = evaluate_starttls_state(
                phase3_status=starttls_res.status,
                advertised_frame=starttls_res.advertised_frame,
                command_frame=starttls_res.command_frame,
                response_frame=starttls_res.response_frame,
                response_code=starttls_res.response_code,
                tls_handshake_observed=tls_observed,
            )

            # Step 7: Build EmailSession record
            start_dt = (
                datetime.fromtimestamp(flow.start_time, tz=timezone.utc)
                if flow.start_time > 0
                else None
            )
            end_dt = (
                datetime.fromtimestamp(flow.end_time, tz=timezone.utc)
                if flow.end_time > 0
                else None
            )

            email_sess = EmailSession(
                job_id=job.id,
                session_index=session_index,
                client_ip=flow.client_ip,
                client_port=flow.client_port,
                server_ip=flow.server_ip,
                server_port=flow.server_port,
                protocol=classification.protocol,
                is_tls_implicit=classification.is_tls_implicit or (tls_observed and starttls_res.status == StarttlsStatus.NOT_OBSERVED),
                starttls_state=st_eval.status,
                start_time=start_dt,
                end_time=end_dt,
                packet_count=flow.packet_count,
                bytes_transferred=flow.bytes_transferred,
                banner=classification.banner,
                hostname=client_hello.sni_hostname if client_hello else None,
            )
            db.add(email_sess)
            await db.flush()  # Generate email_sess.id

            # Step 8: Persist StarttlsState record
            st_state: Optional[StarttlsState] = None
            if st_eval.status != StarttlsStatus.NOT_OBSERVED or starttls_res.advertised_frame:
                st_state = StarttlsState(
                    session_id=email_sess.id,
                    observed_state=st_eval.status,
                    advertised_in_frame=st_eval.advertised_in_frame,
                    command_in_frame=st_eval.command_in_frame,
                    response_in_frame=st_eval.response_in_frame,
                    response_code=st_eval.response_code,
                    is_downgrade_detected=st_eval.is_downgrade_detected,
                    state_details_json=json.dumps({"details": st_eval.details}),
                )
                db.add(st_state)

            # Step 9: Persist TlsHandshake record if TLS observed
            tls_db: Optional[TlsHandshake] = None
            if tls_observed:
                offered_versions_str = (
                    json.dumps([parse_client_hello(b"").legacy_version_name] if False else [c for c in [client_hello.legacy_version_name] + [f"0x{v:04x}" for v in client_hello.supported_versions]])
                    if client_hello
                    else None
                )

                handshake_status = "COMPLETED" if server_hello else "ATTEMPTED"

                tls_db = TlsHandshake(
                    session_id=email_sess.id,
                    client_hello_frame=client_hello.frame_number if client_hello else None,
                    server_hello_frame=server_hello.frame_number if server_hello else None,
                    offered_tls_versions=offered_versions_str,
                    negotiated_tls_version=server_hello.negotiated_tls_version if server_hello else None,
                    client_cipher_suites=json.dumps(client_hello.cipher_suites) if client_hello else None,
                    negotiated_cipher_suite=server_hello.cipher_name if server_hello else None,
                    key_exchange_group=server_hello.key_exchange if server_hello else None,
                    is_forward_secrecy=server_hello.is_forward_secrecy if server_hello else None,
                    sni_hostname=client_hello.sni_hostname if client_hello else None,
                    alpn_protocols=json.dumps(client_hello.alpn_protocols) if client_hello else None,
                    handshake_status=handshake_status,
                    raw_client_hello_bytes=client_hello.raw_bytes if client_hello else None,
                    raw_server_hello_bytes=server_hello.raw_bytes if server_hello else None,
                )
                db.add(tls_db)

            # Step 10: Persist Certificate and CertificateChain records if present
            cert_db: Optional[Certificate] = None
            chain_db: Optional[CertificateChain] = None
            if cert_msg and cert_msg.der_certificates:
                cap_ts = flow.start_time if flow.start_time > 0 else flow.end_time
                chain_res = analyze_certificate_chain(cert_msg.der_certificates, capture_timestamp=cap_ts)

                for cert_idx, parsed_cert in enumerate(chain_res.parsed_certificates):
                    c_rec = Certificate(
                        session_id=email_sess.id,
                        certificate_index=cert_idx,
                        is_server_cert=(cert_idx == 0),
                        subject_dn=parsed_cert.subject_dn,
                        issuer_dn=parsed_cert.issuer_dn,
                        serial_number=parsed_cert.serial_number,
                        not_before=parsed_cert.not_before,
                        not_after=parsed_cert.not_after,
                        public_key_type=parsed_cert.public_key_type,
                        public_key_size_bits=parsed_cert.public_key_size_bits,
                        signature_algorithm=parsed_cert.signature_algorithm,
                        is_weak_signature=parsed_cert.is_weak_signature,
                        sha256_fingerprint=parsed_cert.sha256_fingerprint,
                        sha1_fingerprint=parsed_cert.sha1_fingerprint,
                        is_self_signed=parsed_cert.is_self_signed,
                        is_valid_at_capture=parsed_cert.is_valid_at_capture,
                        san_domains=parsed_cert.san_domains_str,
                        raw_der_bytes=parsed_cert.raw_der_bytes,
                    )
                    db.add(c_rec)
                    if cert_idx == 0:
                        cert_db = c_rec

                chain_db = CertificateChain(
                    session_id=email_sess.id,
                    chain_length=chain_res.chain_length,
                    is_chain_complete=chain_res.is_chain_complete,
                    validation_status=chain_res.validation_status,
                    root_issuer_dn=chain_res.root_issuer_dn,
                    leaf_subject_dn=chain_res.leaf_subject_dn,
                )
                db.add(chain_db)

            # Step 11: Evaluate Security Rules & Calculate Risk Score
            findings, evidence_recs = evaluate_rules_for_session(
                session=email_sess,
                job_id=job.id,
                capture_id=capture.id,
                rules=active_rules,
                tls=tls_db,
                cert=cert_db,
                chain=chain_db,
                stls=st_state,
            )

            for f in findings:
                db.add(f)
            for ev in evidence_recs:
                db.add(ev)

            # Compute transparent Session Risk Score
            sess_score, _ = calculate_session_risk_score(findings, risk_config)
            email_sess.risk_score = sess_score
            session_risk_scores.append(sess_score)

            created_sessions.append(email_sess)

        # Step 12: Calculate Aggregate AnalysisJob Risk Score
        job_risk = calculate_job_risk_score(session_risk_scores)
        job.overall_risk_score = job_risk

        # Update AnalysisJob completed state
        job.status = JobStatus.COMPLETED
        job.total_sessions = len(created_sessions)
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()

        log.info(
            "pipeline_completed",
            capture_id=capture.id,
            job_id=job.id,
            total_sessions=len(created_sessions),
            job_risk_score=job_risk,
        )

        return created_sessions

    except Exception as exc:
        job.status = JobStatus.FAILED
        job.error_message = str(exc)
        await db.commit()
        log.error("pipeline_failed", job_id=job.id, error=str(exc))
        raise
