"""
X.509 Certificate & Chain Analyzer.
Uses cryptography library to dissect DER encoded certificates, extract security parameters,
SANs, public key traits, signature algorithms, and evaluate capture-time validity.
"""

import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, x25519, x448


@dataclass
class X509CertAnalysis:
    subject_dn: str
    issuer_dn: str
    common_name: Optional[str]
    organization: Optional[str]
    organizational_unit: Optional[str]
    serial_number: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    public_key_type: str
    public_key_size_bits: Optional[int]
    signature_algorithm: str
    is_weak_signature: bool
    sha256_fingerprint: str
    sha1_fingerprint: str
    is_self_signed: bool
    san_domains: List[str] = field(default_factory=list)
    san_domains_str: Optional[str] = None
    is_valid_at_capture: Optional[bool] = None
    raw_der_bytes: bytes = b""


@dataclass
class CertificateChainAnalysis:
    chain_length: int
    is_chain_complete: bool
    validation_status: str
    root_issuer_dn: Optional[str]
    leaf_subject_dn: Optional[str]
    parsed_certificates: List[X509CertAnalysis] = field(default_factory=list)


def _get_dn_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    """Helper to extract attribute value from x509.Name by OID."""
    try:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    except Exception:
        pass
    return None


def parse_x509_certificate(
    der_bytes: bytes,
    capture_timestamp: Optional[float] = None
) -> Optional[X509CertAnalysis]:
    """
    Parse DER encoded X.509 certificate and evaluate attributes & capture-time validity.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)

        # Subject & Issuer Distinguished Names
        subject_dn = cert.subject.rfc4514_string()
        issuer_dn = cert.issuer.rfc4514_string()

        common_name = _get_dn_attribute(cert.subject, x509.NameOID.COMMON_NAME)
        organization = _get_dn_attribute(cert.subject, x509.NameOID.ORGANIZATION_NAME)
        organizational_unit = _get_dn_attribute(cert.subject, x509.NameOID.ORGANIZATIONAL_UNIT_NAME)

        serial_number = hex(cert.serial_number)

        # Validity Dates
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            # Fallback for older cryptography versions
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        # Public Key details
        pub_key = cert.public_key()
        pub_key_type = "UNKNOWN"
        pub_key_bits: Optional[int] = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_type = "RSA"
            pub_key_bits = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_type = "EC"
            pub_key_bits = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_type = "DSA"
            pub_key_bits = pub_key.key_size
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
            pub_key_type = "Ed25519"
            pub_key_bits = 256
        elif isinstance(pub_key, (ed448.Ed448PublicKey, x448.X448PublicKey)):
            pub_key_type = "Ed448"
            pub_key_bits = 448

        # Signature Algorithm & Weakness
        sig_alg = cert.signature_algorithm_oid._name
        if sig_alg == "unknown":
            sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "UNKNOWN"

        sig_alg_upper = sig_alg.upper()
        is_weak_signature = any(weak in sig_alg_upper for weak in ("SHA1", "SHA-1", "MD5", "MD2", "MD4"))

        # Fingerprints
        sha256_fp = cert.fingerprint(hashes.SHA256()).hex().lower()
        sha1_fp = cert.fingerprint(hashes.SHA1()).hex().lower()

        # Self-signed status
        is_self_signed = (cert.subject == cert.issuer)

        # SAN Domains
        san_domains: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_obj: x509.SubjectAlternativeName = san_ext.value
            for name_item in san_obj:
                if isinstance(name_item, (x509.DNSName, x509.IPAddress)):
                    san_domains.append(str(name_item.value))
        except x509.ExtensionNotFound:
            pass

        san_domains_str = json.dumps(san_domains) if san_domains else None

        # Capture-Time Validity Evaluation
        is_valid_at_capture: Optional[bool] = None
        if capture_timestamp is not None:
            cap_dt = datetime.fromtimestamp(capture_timestamp, tz=timezone.utc)
            is_valid_at_capture = (not_before <= cap_dt <= not_after)

        return X509CertAnalysis(
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            public_key_type=pub_key_type,
            public_key_size_bits=pub_key_bits,
            signature_algorithm=sig_alg,
            is_weak_signature=is_weak_signature,
            sha256_fingerprint=sha256_fp,
            sha1_fingerprint=sha1_fp,
            is_self_signed=is_self_signed,
            san_domains=san_domains,
            san_domains_str=san_domains_str,
            is_valid_at_capture=is_valid_at_capture,
            raw_der_bytes=der_bytes,
        )

    except Exception:
        return None


def analyze_certificate_chain(
    der_certs: List[bytes],
    capture_timestamp: Optional[float] = None
) -> CertificateChainAnalysis:
    """
    Parse an observed list of DER certificates (leaf at index 0, intermediates at 1..N)
    and compute chain completeness and validity summary.
    """
    parsed: List[X509CertAnalysis] = []
    for der in der_certs:
        cert_info = parse_x509_certificate(der, capture_timestamp=capture_timestamp)
        if cert_info:
            parsed.append(cert_info)

    if not parsed:
        return CertificateChainAnalysis(
            chain_length=0,
            is_chain_complete=False,
            validation_status="INSUFFICIENT_EVIDENCE",
            root_issuer_dn=None,
            leaf_subject_dn=None,
            parsed_certificates=[],
        )

    leaf = parsed[0]
    last = parsed[-1]

    chain_length = len(parsed)
    is_chain_complete = last.is_self_signed

    # Determine chain validation status at capture
    validation_status = "VALID_AT_CAPTURE"

    # Check if any certificate was invalid at capture timestamp
    for c in parsed:
        if c.is_valid_at_capture is False:
            cap_dt = datetime.fromtimestamp(capture_timestamp, tz=timezone.utc) if capture_timestamp else None
            if cap_dt and c.not_before and cap_dt < c.not_before:
                validation_status = "NOT_YET_VALID_AT_CAPTURE"
            else:
                validation_status = "EXPIRED_AT_CAPTURE"
            break
    else:
        if leaf.is_self_signed:
            validation_status = "SELF_SIGNED"
        elif not is_chain_complete:
            validation_status = "INCOMPLETE_CHAIN"

    return CertificateChainAnalysis(
        chain_length=chain_length,
        is_chain_complete=is_chain_complete,
        validation_status=validation_status,
        root_issuer_dn=last.issuer_dn,
        leaf_subject_dn=leaf.subject_dn,
        parsed_certificates=parsed,
    )
