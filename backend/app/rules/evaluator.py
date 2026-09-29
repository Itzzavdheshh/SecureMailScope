"""
Deterministic Security Rule Evaluator.
Evaluates loaded security rules against extracted forensic data (EmailSession, TlsHandshake, Certificate, StarttlsState).
Creates Finding and Evidence records with full packet lineage. Safe condition evaluation without eval().
"""

import uuid
from enum import Enum
import json
from typing import Dict, List, Optional, Tuple, Any
import structlog

from app.models.enums import Confidence, EvidenceStatus, FindingCategory, Severity
from app.models.session import EmailSession, StarttlsState, TlsHandshake
from app.models.certificate import Certificate, CertificateChain
from app.models.finding import Finding, Evidence
from app.rules.schema import RuleDefinition

log = structlog.get_logger(__name__)


def evaluate_condition(actual_val: Any, operator: str, target_val: Any) -> bool:
    """Safely evaluate detection condition operator against actual value."""
    if actual_val is None:
        return False

    op = operator.lower()
    try:
        if op in ("equals", "==", "is"):
            act_str = str(actual_val).upper()
            tgt_str = str(target_val).upper()
            if act_str == tgt_str:
                return True
            if (act_str in ("REJECTED", "FAILED") and tgt_str in ("REJECTED", "FAILED")):
                return True
            return False

        elif op in ("not_equals", "!="):
            return actual_val != target_val

        elif op == "in":
            if isinstance(target_val, list):
                return actual_val in target_val or str(actual_val) in [str(x) for x in target_val]
            return False

        elif op in ("not_in", "not in"):
            if isinstance(target_val, list):
                return actual_val not in target_val and str(actual_val) not in [str(x) for x in target_val]
            return True

        elif op in ("less_than", "<"):
            return float(actual_val) < float(target_val)

        elif op in ("greater_than", ">"):
            return float(actual_val) > float(target_val)

        elif op == "contains":
            return str(target_val).lower() in str(actual_val).lower()

        elif op == "contains_any":
            if isinstance(target_val, list):
                act_str = str(actual_val).lower()
                return any(str(item).lower() in act_str for item in target_val)
            return False

    except Exception:
        return False

    return False


def get_session_attribute(
    field_name: str,
    session: EmailSession,
    tls: Optional[TlsHandshake],
    cert: Optional[Certificate],
    chain: Optional[CertificateChain],
    stls: Optional[StarttlsState]
) -> Tuple[Any, Optional[int], str]:
    """
    Extract field value, evidence frame number, and protocol layer for evaluation.
    Returns (observed_value, frame_number, protocol_layer).
    """
    val: Any = None
    frame: Optional[int] = None
    layer: str = "PROTOCOL"

    # TLS Attributes
    if field_name == "negotiated_tls_version":
        val = tls.negotiated_tls_version if tls else None
        frame = tls.server_hello_frame if tls else None
        layer = "TLS"

    elif field_name in ("negotiated_cipher_suite", "cipher_suite_name"):
        val = tls.negotiated_cipher_suite if tls else None
        frame = tls.server_hello_frame if tls else None
        layer = "TLS"

    elif field_name == "forward_secrecy":
        val = tls.is_forward_secrecy if tls else None
        frame = tls.server_hello_frame if tls else None
        layer = "TLS"

    elif field_name == "key_exchange_algorithm":
        val = tls.key_exchange_group if tls else None
        frame = tls.server_hello_frame if tls else None
        layer = "TLS"

    elif field_name == "cipher_family":
        cs_name = (tls.negotiated_cipher_suite or "").upper() if tls else ""
        if "RC4" in cs_name:
            val = "RC4"
        elif "3DES" in cs_name or "DES" in cs_name:
            val = "3DES"
        elif "NULL" in cs_name:
            val = "NULL"
        elif "EXPORT" in cs_name:
            val = "EXPORT"
        elif "ANON" in cs_name or "ADH" in cs_name:
            val = "ANON"
        else:
            val = cs_name
        frame = tls.server_hello_frame if tls else None
        layer = "TLS"

    elif field_name == "version_downgrade_detected":
        val = stls.is_downgrade_detected if stls else False
        frame = stls.command_in_frame if stls else None
        layer = "STARTTLS"

    # Certificate Attributes
    elif field_name == "valid_at_capture":
        val = cert.is_valid_at_capture if cert else None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "not_yet_valid_at_capture":
        # TRUE only when the capture timestamp is strictly before the certificate's
        # notBefore date -- i.e. the cert was not yet valid at the time of capture.
        # IMPORTANT: is_valid_at_capture is False for BOTH expired AND not-yet-valid certs,
        # so we must NOT use it as a proxy here. Compare capture time vs not_before directly.
        if cert and cert.not_before is not None and session.start_time is not None:
            from datetime import timezone as _tz
            cap_dt = session.start_time
            nb = cert.not_before
            if cap_dt.tzinfo is None:
                cap_dt = cap_dt.replace(tzinfo=_tz.utc)
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=_tz.utc)
            val = cap_dt < nb
        else:
            val = None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "public_key_size":
        val = cert.public_key_size_bits if cert else None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "public_key_algorithm":
        val = cert.public_key_type if cert else None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name in ("signature_algorithm_oid", "signature_algorithm"):
        val = cert.signature_algorithm if cert else None
        if cert and cert.is_weak_signature:
            val = "1.2.840.113549.1.1.5"  # sha1 OID alias for rule matching
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "self_signed":
        val = cert.is_self_signed if cert else None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "has_san_dns":
        val = (cert.san_domains is not None and cert.san_domains != "[]") if cert else None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "chain_complete":
        val = chain.is_chain_complete if chain else None
        frame = tls.server_hello_frame if tls else None
        layer = "X509"

    elif field_name == "starttls_state":
        val = session.starttls_state.value if isinstance(session.starttls_state, Enum) else str(session.starttls_state)
        if stls and stls.observed_state:
            val = stls.observed_state.value if isinstance(stls.observed_state, Enum) else str(stls.observed_state)
        frame = stls.command_in_frame or stls.response_in_frame or stls.advertised_in_frame if stls else None
        layer = "STARTTLS"

        # If STARTTLS is NOT_OBSERVED and no capability/banner frame was captured, treat as insufficient evidence
        if val == "NOT_OBSERVED" and frame is None and session.banner is None:
            val = None


    elif field_name == "uses_implicit_tls":
        val = session.is_tls_implicit
        frame = tls.client_hello_frame if tls else None
        layer = "PROTOCOL"

    return val, frame, layer


def evaluate_rules_for_session(
    session: EmailSession,
    job_id: str,
    capture_id: str,
    rules: List[RuleDefinition],
    tls: Optional[TlsHandshake] = None,
    cert: Optional[Certificate] = None,
    chain: Optional[CertificateChain] = None,
    stls: Optional[StarttlsState] = None,
) -> Tuple[List[Finding], List[Evidence]]:
    """
    Evaluate deterministic rules against session forensic objects without lazy loading.
    Returns generated Finding and Evidence records.
    """
    if tls is None and hasattr(session, "__dict__") and "tls_handshake" in session.__dict__:
        tls = session.tls_handshake
    if cert is None and hasattr(session, "__dict__") and "certificates" in session.__dict__ and session.certificates:
        cert = session.certificates[0]
    if chain is None and hasattr(session, "__dict__") and "certificate_chain" in session.__dict__:
        chain = session.certificate_chain
    if stls is None and hasattr(session, "__dict__") and "starttls_details" in session.__dict__:
        stls = session.starttls_details

    findings: List[Finding] = []
    evidence_records: List[Evidence] = []

    cap_ts = session.start_time.timestamp() if session.start_time else 0.0

    for rule in rules:
        if not rule.enabled:
            continue

        # Extract target field value
        det = rule.detection
        act_val, frame_num, layer = get_session_attribute(det.field, session, tls, cert, chain, stls)

        # Missing evidence handling
        if act_val is None:
            continue

        # Primary condition evaluation
        triggered = evaluate_condition(act_val, det.condition, det.value)

        # Additional condition evaluation if defined
        if triggered and rule.additional_condition:
            add_cond = rule.additional_condition
            add_val, _, _ = get_session_attribute(add_cond.field, session, tls, cert, chain, stls)
            triggered = evaluate_condition(add_val, add_cond.condition, add_cond.value)

        if triggered:
            # Create Finding with explicit UUID id so finding.id is immediately valid
            finding_id = str(uuid.uuid4())
            finding = Finding(
                id=finding_id,
                job_id=job_id,
                session_id=session.id,
                rule_id=rule.id,
                title=rule.title,
                category=rule.category or FindingCategory.PROTOCOL_ANOMALY,
                severity=rule.severity,
                confidence=Confidence.HIGH if frame_num else Confidence.MEDIUM,
                status=EvidenceStatus.OBSERVED,
                description=rule.description,
                remediation_recommendation=rule.remediation,
            )
            findings.append(finding)

            # Create Evidence record linked to finding_id
            ev_frame = frame_num if frame_num is not None else 1
            ev = Evidence(
                finding_id=finding_id,
                capture_id=capture_id,
                session_id=session.id,
                frame_number=ev_frame,
                packet_timestamp=cap_ts,
                protocol_layer=layer,
                field_name=det.field,
                observed_value=str(act_val),
                evidence_status=EvidenceStatus.OBSERVED,
            )
            evidence_records.append(ev)

    return findings, evidence_records
