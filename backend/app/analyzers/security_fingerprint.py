"""Versioned, evidence-derived cryptographic security fingerprints."""

import hashlib
import json
from typing import Any, Dict, Iterable, Optional

from app.analyzers.tls_parser import parse_client_hello, parse_server_hello


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _clean(value: Optional[str]) -> Optional[str]:
    return value.strip() if value and value.strip() else None


def build_security_fingerprint(
    session: Any,
    capture_id: str,
    job: Any,
    infrastructure_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a normalized fingerprint from persisted facts, without new inference."""
    tls = session.tls_handshake
    starttls = session.starttls_details
    client_hello = (
        parse_client_hello(tls.raw_client_hello_bytes, tls.client_hello_frame or 0)
        if tls and tls.raw_client_hello_bytes
        else None
    )
    server_hello = (
        parse_server_hello(tls.raw_server_hello_bytes, tls.server_hello_frame or 0)
        if tls and tls.raw_server_hello_bytes
        else None
    )
    cert = next((item for item in session.certificates if item.is_server_cert), None)
    findings = list(session.findings or [])
    severity_counts: Dict[str, int] = {}
    for finding in findings:
        severity = str(_value(finding.severity))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    ja3 = client_hello.ja3_hash if client_hello else None
    ja3s = server_hello.ja3s_hash if server_hello else None
    starttls_state = _value(session.starttls_state)
    protocol = str(_value(session.protocol))
    stable_profile = {
        "protocol": protocol,
        "is_tls_implicit": bool(session.is_tls_implicit),
        "starttls_state": str(starttls_state),
        "tls_version": _clean(tls.negotiated_tls_version) if tls else None,
        "cipher_suite": _clean(tls.negotiated_cipher_suite) if tls else None,
        "key_exchange_group": _clean(tls.key_exchange_group) if tls else None,
        "forward_secrecy": tls.is_forward_secrecy if tls else None,
        "offered_tls_versions": _clean(tls.offered_tls_versions) if tls else None,
        "offered_cipher_suites": _clean(tls.client_cipher_suites) if tls else None,
        "ja3": ja3,
        "ja3s": ja3s,
        "certificate": {
            "sha256_fingerprint": _clean(cert.sha256_fingerprint).lower() if cert and cert.sha256_fingerprint else None,
            "subject": _clean(cert.subject_dn) if cert else None,
            "issuer": _clean(cert.issuer_dn) if cert else None,
            "sans": cert.san_domains if cert else None,
            "key_type": _clean(cert.public_key_type) if cert else None,
            "key_size_bits": cert.public_key_size_bits if cert else None,
            "signature_algorithm": _clean(cert.signature_algorithm) if cert else None,
            "valid_at_capture": cert.is_valid_at_capture if cert else None,
            "self_signed": cert.is_self_signed if cert else None,
            "chain_status": _clean(session.certificate_chain.validation_status)
            if session.certificate_chain else None,
        },
    }
    # Null means not observed, so it is omitted from the hash rather than asserting absence.
    hash_profile = _without_unknown(stable_profile)
    canonical = json.dumps(hash_profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    fingerprint_hash = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    frames = {
        "client_hello": tls.client_hello_frame if tls else None,
        "server_hello": tls.server_hello_frame if tls else None,
        "starttls_advertised": starttls.advertised_in_frame if starttls else None,
        "starttls_command": starttls.command_in_frame if starttls else None,
        "starttls_response": starttls.response_in_frame if starttls else None,
        "certificate": None,
        "findings": sorted({
            evidence.frame_number
            for finding in findings
            for evidence in (finding.evidence or [])
        }),
    }
    return {
        "fingerprint_version": "1.0.0",
        "identity": {
            "protocol": protocol,
            "server_ip": session.server_ip,
            "server_port": session.server_port,
            "hostname": _clean((tls.sni_hostname if tls else None) or session.hostname),
            "infrastructure_id": infrastructure_id,
        },
        "stable_profile": stable_profile,
        "security_posture": {
            "analysis_job_risk_score": job.overall_risk_score,
            "risk_band": _value(job.risk_band) if job.risk_band is not None else None,
            "session_risk_score": session.risk_score,
            "finding_ids": sorted(f.id for f in findings),
            "severity_distribution": dict(sorted(severity_counts.items())),
        },
        "evidence": {
            "capture_id": capture_id,
            "analysis_job_id": job.id,
            "session_id": session.id,
            "observed_at": session.start_time.isoformat() if session.start_time else None,
            "frames": frames,
        },
        "fingerprint_hash": fingerprint_hash,
        "hash_algorithm": "SHA-256",
        "hash_fields": sorted(_leaf_paths(hash_profile)),
    }


def compare_security_fingerprints(first: Dict[str, Any], second: Dict[str, Any]) -> Dict[str, Any]:
    """Compare observed posture fields; missing-on-either-side values are not changes."""
    left = first.get("stable_profile", {})
    right = second.get("stable_profile", {})
    differences = []
    not_comparable = []
    for path in sorted(set(_leaf_paths(left)) | set(_leaf_paths(right))):
        old = _get_path(left, path)
        new = _get_path(right, path)
        if old is None or new is None:
            if old != new:
                not_comparable.append(path)
        elif old != new:
            differences.append({"field": path, "from": old, "to": new})
    if differences:
        status = "CHANGED"
    elif first.get("fingerprint_hash") == second.get("fingerprint_hash"):
        status = "UNCHANGED"
    else:
        status = "INDETERMINATE"
    return {"status": status, "differences": differences, "not_comparable_fields": not_comparable}


def _without_unknown(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_unknown(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_without_unknown(item) for item in value if item is not None]
    return value


def _leaf_paths(value: Dict[str, Any], prefix: str = "") -> Iterable[str]:
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            yield from _leaf_paths(item, path)
        else:
            yield path


def _get_path(value: Dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
