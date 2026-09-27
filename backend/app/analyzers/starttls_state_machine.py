"""
Complete STARTTLS State Machine.
Combines application-level STARTTLS protocol events with TLS handshake observations
to track formal negotiation states:
NOT_OBSERVED -> ADVERTISED -> ATTEMPTED -> ACCEPTED -> TLS_FOLLOWED
(or REJECTED / ANOMALOUS / DOWNGRADED).
"""

from typing import Optional
from dataclasses import dataclass

from app.models.enums import StarttlsStatus


@dataclass
class StarttlsStateEvaluation:
    status: StarttlsStatus
    advertised_in_frame: Optional[int] = None
    command_in_frame: Optional[int] = None
    response_in_frame: Optional[int] = None
    response_code: Optional[int] = None
    tls_handshake_observed: bool = False
    is_downgrade_detected: bool = False
    details: str = ""


def evaluate_starttls_state(
    phase3_status: StarttlsStatus,
    advertised_frame: Optional[int],
    command_frame: Optional[int],
    response_frame: Optional[int],
    response_code: Optional[int],
    tls_handshake_observed: bool,
    plaintext_after_accepted: bool = False
) -> StarttlsStateEvaluation:
    """
    Evaluate the complete STARTTLS negotiation state machine.
    """
    if phase3_status == StarttlsStatus.ACCEPTED:
        if tls_handshake_observed:
            final_status = StarttlsStatus.ACCEPTED  # TLS_FOLLOWED maps to ACCEPTED + tls_handshake_observed in DB
            details = "STARTTLS command accepted by server and TLS handshake successfully followed."
        elif plaintext_after_accepted:
            final_status = StarttlsStatus.ANOMALOUS
            details = "STARTTLS command accepted, but client continued with plaintext commands without TLS."
        else:
            final_status = StarttlsStatus.ACCEPTED
            details = "STARTTLS command accepted by server, awaiting TLS negotiation."

    elif phase3_status == StarttlsStatus.REJECTED:
        final_status = StarttlsStatus.REJECTED
        details = f"STARTTLS negotiation rejected by server with code {response_code}."

    elif phase3_status == StarttlsStatus.ATTEMPTED:
        final_status = StarttlsStatus.ATTEMPTED
        details = "STARTTLS command sent by client, but no server response was recorded."

    elif phase3_status == StarttlsStatus.ADVERTISED:
        if tls_handshake_observed:
            # TLS started without explicit STARTTLS command (unexpected on STARTTLS port)
            final_status = StarttlsStatus.ANOMALOUS
            details = "TLS handshake observed directly after STARTTLS advertisement without explicit command."
        else:
            final_status = StarttlsStatus.ADVERTISED
            details = "STARTTLS capability advertised by server, but not requested by client."

    else:
        if tls_handshake_observed:
            final_status = StarttlsStatus.NOT_OBSERVED
            details = "Implicit TLS session (no STARTTLS negotiation)."
        else:
            final_status = StarttlsStatus.NOT_OBSERVED
            details = "No STARTTLS activity observed."

    is_downgrade_detected = (phase3_status == StarttlsStatus.REJECTED or plaintext_after_accepted)

    return StarttlsStateEvaluation(
        status=final_status,
        advertised_in_frame=advertised_frame,
        command_in_frame=command_frame,
        response_in_frame=response_frame,
        response_code=response_code,
        tls_handshake_observed=tls_handshake_observed,
        is_downgrade_detected=is_downgrade_detected,
        details=details,
    )
