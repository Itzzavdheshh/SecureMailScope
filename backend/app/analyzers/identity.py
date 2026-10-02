"""
Infrastructure Identity & Cryptographic Profile Analyzer.
Constructs stable, deterministic infrastructure identity keys for observed mail endpoints
and normalizes observed session attributes into structured cryptographic profiles.
"""

import hashlib
import json
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any

from app.models.session import EmailSession, StarttlsState, TlsHandshake
from app.models.certificate import Certificate, CertificateChain


@dataclass
class CryptographicProfile:
    protocol: str
    server_ip: str
    server_port: int
    hostname: Optional[str]
    negotiated_tls_version: Optional[str]
    negotiated_cipher_suite: Optional[str]
    forward_secrecy: Optional[bool]
    key_exchange_algorithm: Optional[str]
    leaf_cert_sha256: Optional[str]
    cert_signature_algorithm: Optional[str]
    cert_public_key_type: Optional[str]
    cert_public_key_bits: Optional[int]
    cert_self_signed: Optional[bool]
    starttls_state: str
    ja3: Optional[str]
    ja3s: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def construct_identity_key(
    server_ip: str,
    server_port: int,
    protocol: str,
    hostname: Optional[str] = None,
    cert_sha256: Optional[str] = None
) -> str:
    """
    Construct a deterministic identity key for an infrastructure endpoint.
    Combines network endpoint (IP, port), protocol, and hostname.
    Certificate SHA-256 fingerprint is tracked within the CryptographicProfile
    to enable drift detection across certificate rotations without splitting infrastructure identity.
    """
    host_str = (hostname or "").strip().lower()
    raw = f"{server_ip}:{server_port}:{protocol.upper()}:{host_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]



def build_cryptographic_profile(
    session: EmailSession,
    tls: Optional[TlsHandshake] = None,
    cert: Optional[Certificate] = None,
    stls: Optional[StarttlsState] = None
) -> CryptographicProfile:
    """
    Extract and normalize observable cryptographic attributes into a CryptographicProfile.
    """
    tls_obj = tls
    if tls_obj is None and hasattr(session, "__dict__") and "tls_handshake" in session.__dict__:
        tls_obj = session.tls_handshake

    cert_obj = cert
    if cert_obj is None and hasattr(session, "__dict__") and "certificates" in session.__dict__ and session.certificates:
        cert_obj = session.certificates[0]

    stls_obj = stls
    if stls_obj is None and hasattr(session, "__dict__") and "starttls_details" in session.__dict__:
        stls_obj = session.starttls_details


    proto_str = session.protocol.value if hasattr(session.protocol, "value") else str(session.protocol)
    stls_str = session.starttls_state.value if hasattr(session.starttls_state, "value") else str(session.starttls_state)
    if stls_obj and stls_obj.observed_state:
        stls_str = stls_obj.observed_state.value if hasattr(stls_obj.observed_state, "value") else str(stls_obj.observed_state)

    return CryptographicProfile(
        protocol=proto_str,
        server_ip=session.server_ip,
        server_port=session.server_port,
        hostname=session.hostname or (tls_obj.sni_hostname if tls_obj else None),
        negotiated_tls_version=tls_obj.negotiated_tls_version if tls_obj else None,
        negotiated_cipher_suite=tls_obj.negotiated_cipher_suite if tls_obj else None,
        forward_secrecy=tls_obj.is_forward_secrecy if tls_obj else None,
        key_exchange_algorithm=tls_obj.key_exchange_group if tls_obj else None,
        leaf_cert_sha256=cert_obj.sha256_fingerprint if cert_obj else None,
        cert_signature_algorithm=cert_obj.signature_algorithm if cert_obj else None,
        cert_public_key_type=cert_obj.public_key_type if cert_obj else None,
        cert_public_key_bits=cert_obj.public_key_size_bits if cert_obj else None,
        cert_self_signed=cert_obj.is_self_signed if cert_obj else None,
        starttls_state=stls_str,
        ja3=None,  # Handshake metadata
        ja3s=None,
    )
