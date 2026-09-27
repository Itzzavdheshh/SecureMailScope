"""
Significant Cryptographic Drift Detector.
Compares observed session cryptographic profile against established infrastructure baseline.
Correlates multiple parameter changes into a single evidence-backed DriftEvent record
using factual, non-speculative forensic language.
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from app.models.enums import DriftEventType
from app.models.infrastructure import DriftEvent, InfrastructureIdentity
from app.analyzers.identity import CryptographicProfile
from app.analyzers.baseline import InfrastructureBaseline, BaselineStatus


@dataclass
class DriftFieldChange:
    field_name: str
    previous_val: Any
    current_val: Any
    description: str


@dataclass
class DriftDetectionResult:
    is_drift_detected: bool
    primary_event_type: Optional[DriftEventType]
    previous_state: Dict[str, Any] = field(default_factory=dict)
    new_state: Dict[str, Any] = field(default_factory=dict)
    delta_description: str = ""
    changed_fields: List[str] = field(default_factory=list)
    risk_delta: float = 0.0


def compare_profiles_for_drift(
    current: CryptographicProfile,
    baseline_profile: Optional[CryptographicProfile],
    baseline_status: BaselineStatus = BaselineStatus.ESTABLISHED,
    current_risk_score: float = 0.0,
    baseline_risk_score: float = 0.0,
) -> DriftDetectionResult:
    """
    Compare current session cryptographic profile against baseline.
    Detects TLS version downgrade, cipher downgrade, cert change, STARTTLS disruption.
    Correlates multiple change dimensions into a single factual result.
    """
    if not baseline_profile or baseline_status in (BaselineStatus.NO_BASELINE, BaselineStatus.PROVISIONAL):
        return DriftDetectionResult(
            is_drift_detected=False,
            primary_event_type=None,
            delta_description="No established baseline available for drift comparison."
        )

    b = baseline_profile
    c = current
    changes: List[DriftFieldChange] = []

    # 1. TLS Version Change
    if b.negotiated_tls_version and c.negotiated_tls_version and b.negotiated_tls_version != c.negotiated_tls_version:
        changes.append(DriftFieldChange(
            field_name="negotiated_tls_version",
            previous_val=b.negotiated_tls_version,
            current_val=c.negotiated_tls_version,
            description=f"Negotiated TLS version changed from {b.negotiated_tls_version} to {c.negotiated_tls_version}."
        ))

    # 2. Cipher Suite Change / Forward Secrecy Change
    if b.negotiated_cipher_suite and c.negotiated_cipher_suite and b.negotiated_cipher_suite != c.negotiated_cipher_suite:
        changes.append(DriftFieldChange(
            field_name="negotiated_cipher_suite",
            previous_val=b.negotiated_cipher_suite,
            current_val=c.negotiated_cipher_suite,
            description=f"Negotiated cipher suite changed from {b.negotiated_cipher_suite} to {c.negotiated_cipher_suite}."
        ))

    if b.forward_secrecy is True and c.forward_secrecy is False:
        changes.append(DriftFieldChange(
            field_name="forward_secrecy",
            previous_val=True,
            current_val=False,
            description="Observed key exchange changed from Forward Secrecy to static key exchange."
        ))

    # 3. Certificate Change
    if b.leaf_cert_sha256 and c.leaf_cert_sha256 and b.leaf_cert_sha256 != c.leaf_cert_sha256:
        changes.append(DriftFieldChange(
            field_name="leaf_cert_sha256",
            previous_val=b.leaf_cert_sha256,
            current_val=c.leaf_cert_sha256,
            description=f"Certificate SHA-256 fingerprint changed from {b.leaf_cert_sha256[:16]}... to {c.leaf_cert_sha256[:16]}..."
        ))

    if b.cert_signature_algorithm and c.cert_signature_algorithm and b.cert_signature_algorithm != c.cert_signature_algorithm:
        changes.append(DriftFieldChange(
            field_name="cert_signature_algorithm",
            previous_val=b.cert_signature_algorithm,
            current_val=c.cert_signature_algorithm,
            description=f"Certificate signature algorithm changed from {b.cert_signature_algorithm} to {c.cert_signature_algorithm}."
        ))

    # 4. STARTTLS Behavior Change (Requires explicitly observed negative state, NOT unobserved activity)
    if b.starttls_state in ("ACCEPTED", "TLS_FOLLOWED") and c.starttls_state in ("REJECTED", "FAILED", "ANOMALOUS", "DISABLED"):
        changes.append(DriftFieldChange(
            field_name="starttls_state",
            previous_val=b.starttls_state,
            current_val=c.starttls_state,
            description=f"STARTTLS negotiation behavior changed from {b.starttls_state} to {c.starttls_state}."
        ))


    if not changes:
        return DriftDetectionResult(is_drift_detected=False, primary_event_type=None)

    # Determine primary event type
    primary_event_type = DriftEventType.CERT_CHANGED
    for ch in changes:
        if ch.field_name == "negotiated_tls_version":
            primary_event_type = DriftEventType.TLS_VERSION_DOWNGRADE
            break
        elif ch.field_name in ("negotiated_cipher_suite", "forward_secrecy"):
            primary_event_type = DriftEventType.CIPHER_DOWNGRADE
            break
        elif ch.field_name == "starttls_state":
            primary_event_type = DriftEventType.STARTTLS_DISABLED
            break

    prev_dict = {ch.field_name: ch.previous_val for ch in changes}
    new_dict = {ch.field_name: ch.current_val for ch in changes}

    delta_desc = "Cryptographic configuration drift detected: " + "; ".join(ch.description for ch in changes)
    risk_delta = max(0.0, round(current_risk_score - baseline_risk_score, 1))

    return DriftDetectionResult(
        is_drift_detected=True,
        primary_event_type=primary_event_type,
        previous_state=prev_dict,
        new_state=new_dict,
        delta_description=delta_desc,
        changed_fields=[ch.field_name for ch in changes],
        risk_delta=risk_delta,
    )
