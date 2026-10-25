"""
Canonical Posture Evolution Foundation.

Separates Infrastructure Identity from Cryptographic Security Fingerprint
and tracks how observed cryptographic posture evolves over time.
Classifies changes into:
- NO_MEANINGFUL_CHANGE
- CERTIFICATE_ROTATION
- CERTIFICATE_IMPROVEMENT
- CERTIFICATE_DEGRADATION
- PROTOCOL_DOWNGRADE
- CIPHER_DOWNGRADE
- KEY_EXCHANGE_DOWNGRADE
- CRYPTOGRAPHIC_CONFIGURATION_CHANGE
- SECURITY_POSTURE_REGRESSION
- SECURITY_POSTURE_IMPROVEMENT
- INDETERMINATE
"""

from enum import Enum
from typing import Any, Dict, List, Optional


class PostureEvolutionType(str, Enum):
    NO_MEANINGFUL_CHANGE = "NO_MEANINGFUL_CHANGE"
    CERTIFICATE_ROTATION = "CERTIFICATE_ROTATION"
    CERTIFICATE_IMPROVEMENT = "CERTIFICATE_IMPROVEMENT"
    CERTIFICATE_DEGRADATION = "CERTIFICATE_DEGRADATION"
    PROTOCOL_DOWNGRADE = "PROTOCOL_DOWNGRADE"
    CIPHER_DOWNGRADE = "CIPHER_DOWNGRADE"
    KEY_EXCHANGE_DOWNGRADE = "KEY_EXCHANGE_DOWNGRADE"
    CRYPTOGRAPHIC_CONFIGURATION_CHANGE = "CRYPTOGRAPHIC_CONFIGURATION_CHANGE"
    SECURITY_POSTURE_REGRESSION = "SECURITY_POSTURE_REGRESSION"
    SECURITY_POSTURE_IMPROVEMENT = "SECURITY_POSTURE_IMPROVEMENT"
    INDETERMINATE = "INDETERMINATE"


_TLS_VERSION_RANKS: Dict[str, int] = {
    "SSL 2.0": 1,
    "SSLV2": 1,
    "SSL 3.0": 2,
    "SSLV3": 2,
    "TLS 1.0": 3,
    "TLSV1.0": 3,
    "TLS 1.1": 4,
    "TLSV1.1": 4,
    "TLS 1.2": 5,
    "TLSV1.2": 5,
    "TLS 1.3": 6,
    "TLSV1.3": 6,
}


def _tls_version_rank(version: Optional[str]) -> int:
    if not version:
        return 0
    norm = version.strip().upper()
    return _TLS_VERSION_RANKS.get(norm, 0)


def _is_weak_cipher(cipher_name: Optional[str]) -> bool:
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return any(weak in upper for weak in ("RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "ADH"))


def _sig_algo_rank(sig_algo: Optional[str]) -> int:
    if not sig_algo:
        return 0
    upper = sig_algo.upper()
    if "MD5" in upper:
        return 1
    if "SHA1" in upper or "SHA-1" in upper:
        return 2
    if "SHA256" in upper or "SHA-256" in upper:
        return 3
    if "SHA384" in upper or "SHA-384" in upper or "SHA512" in upper or "SHA-512" in upper:
        return 4
    if "ED25519" in upper or "ED448" in upper:
        return 5
    return 3


def classify_posture_evolution(
    first_fingerprint: Dict[str, Any],
    second_fingerprint: Dict[str, Any],
    differences: Optional[List[Dict[str, Any]]] = None,
    not_comparable_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Classify transition from first_fingerprint (Observation A) to second_fingerprint (Observation B).

    Guarantees:
    - Certificate rotation without cryptographic degradation is classified as CERTIFICATE_ROTATION,
      NOT as a security regression or configuration degradation.
    - True cryptographic downgrades (protocol version, cipher, forward secrecy) are classified with
      exact regression categories.
    - Deterministic, explainable output with structured category, is_regression, and explanation.
    """
    first_hash = first_fingerprint.get("fingerprint_hash")
    second_hash = second_fingerprint.get("fingerprint_hash")

    first_profile = first_fingerprint.get("stable_profile", {})
    second_profile = second_fingerprint.get("stable_profile", {})

    diffs = differences if differences is not None else []
    not_comp = not_comparable_fields if not_comparable_fields is not None else []

    # If identical hashes and no differences
    if first_hash == second_hash and not diffs:
        return {
            "classification": PostureEvolutionType.NO_MEANINGFUL_CHANGE.value,
            "primary_category": "NONE",
            "is_regression": False,
            "is_improvement": False,
            "is_certificate_only": False,
            "explanation": "No observable cryptographic or certificate differences between sessions.",
            "field_differences_count": 0,
        }

    # If no comparable fields could be evaluated
    if not diffs and not_comp and first_hash != second_hash:
        return {
            "classification": PostureEvolutionType.INDETERMINATE.value,
            "primary_category": "INDETERMINATE",
            "is_regression": False,
            "is_improvement": False,
            "is_certificate_only": False,
            "explanation": "Observations could not be compared because fields were not mutually observed.",
            "field_differences_count": 0,
        }

    diff_fields = {item.get("field", "") for item in diffs}

    # Check if differences are exclusively within certificate / chain metadata
    cert_fields = {
        "certificate.sha256_fingerprint",
        "certificate.serial_number",
        "certificate.validity_not_after",
        "certificate.validity_not_before",
        "certificate.subject",
        "certificate.issuer",
        "certificate.san_domains",
        "certificate_chain.length",
        "certificate_chain.sha256_fingerprints",
        "certificate.signature_algorithm",
        "certificate.key_type",
        "certificate.key_size_bits",
        "certificate.valid_at_capture",
    }
    is_cert_only = bool(diff_fields and diff_fields.issubset(cert_fields))

    # 1. Certificate Analysis
    if is_cert_only:
        cert_a = first_profile.get("certificate") or {}
        cert_b = second_profile.get("certificate") or {}

        sig_a = _sig_algo_rank(cert_a.get("signature_algorithm"))
        sig_b = _sig_algo_rank(cert_b.get("signature_algorithm"))

        bits_a = cert_a.get("key_size_bits") or 0
        bits_b = cert_b.get("key_size_bits") or 0

        valid_a = cert_a.get("valid_at_capture")
        valid_b = cert_b.get("valid_at_capture")

        # Degradation checks
        if valid_a is True and valid_b is False:
            return {
                "classification": PostureEvolutionType.CERTIFICATE_DEGRADATION.value,
                "primary_category": "REGRESSION",
                "is_regression": True,
                "is_improvement": False,
                "is_certificate_only": True,
                "explanation": "Replaced certificate is invalid or expired at time of capture.",
                "field_differences_count": len(diffs),
            }
        if sig_b < sig_a and sig_b <= 2:  # Replaced with SHA-1 or MD5
            return {
                "classification": PostureEvolutionType.CERTIFICATE_DEGRADATION.value,
                "primary_category": "REGRESSION",
                "is_regression": True,
                "is_improvement": False,
                "is_certificate_only": True,
                "explanation": f"Replaced certificate downgraded signature algorithm from {cert_a.get('signature_algorithm')} to {cert_b.get('signature_algorithm')}.",
                "field_differences_count": len(diffs),
            }
        if bits_a > bits_b and bits_b < 2048 and (cert_b.get("key_type") or "").upper() == "RSA":
            return {
                "classification": PostureEvolutionType.CERTIFICATE_DEGRADATION.value,
                "primary_category": "REGRESSION",
                "is_regression": True,
                "is_improvement": False,
                "is_certificate_only": True,
                "explanation": f"Replaced certificate decreased RSA key size from {bits_a} to {bits_b} bits.",
                "field_differences_count": len(diffs),
            }

        # Improvement checks
        if (valid_a is False and valid_b is True) or (sig_b > sig_a) or (bits_b > bits_a and bits_a > 0):
            return {
                "classification": PostureEvolutionType.CERTIFICATE_IMPROVEMENT.value,
                "primary_category": "IMPROVEMENT",
                "is_regression": False,
                "is_improvement": True,
                "is_certificate_only": True,
                "explanation": "Certificate renewed with stronger cryptographic parameters or restored validity.",
                "field_differences_count": len(diffs),
            }

        # Standard benign rotation
        return {
            "classification": PostureEvolutionType.CERTIFICATE_ROTATION.value,
            "primary_category": "ROTATION",
            "is_regression": False,
            "is_improvement": False,
            "is_certificate_only": True,
            "explanation": "Certificate rotated with equivalent cryptographic parameters. No configuration regression.",
            "field_differences_count": len(diffs),
        }

    # 2. Cryptographic Protocol & Parameter Analysis
    regressions: List[str] = []
    improvements: List[str] = []

    # TLS Version
    ver_a = _tls_version_rank(first_profile.get("tls_version"))
    ver_b = _tls_version_rank(second_profile.get("tls_version"))
    if ver_a > 0 and ver_b > 0 and ver_a != ver_b:
        if ver_b < ver_a:
            regressions.append(
                f"Protocol downgraded from {first_profile.get('tls_version')} to {second_profile.get('tls_version')}"
            )
        else:
            improvements.append(
                f"Protocol upgraded from {first_profile.get('tls_version')} to {second_profile.get('tls_version')}"
            )

    # STARTTLS State
    stls_a = first_profile.get("starttls_state")
    stls_b = second_profile.get("starttls_state")
    if stls_a and stls_b and stls_a != stls_b:
        if stls_a == "ACCEPTED" and stls_b in ("REJECTED", "NOT_OFFERED", "STRIPPED"):
            regressions.append(f"STARTTLS capability degraded from {stls_a} to {stls_b}")
        elif stls_b == "ACCEPTED" and stls_a in ("REJECTED", "NOT_OFFERED", "STRIPPED"):
            improvements.append(f"STARTTLS capability restored from {stls_a} to {stls_b}")

    # Cipher Suite
    cipher_a = first_profile.get("cipher_suite")
    cipher_b = second_profile.get("cipher_suite")
    if cipher_a and cipher_b and cipher_a != cipher_b:
        weak_a = _is_weak_cipher(cipher_a)
        weak_b = _is_weak_cipher(cipher_b)
        if not weak_a and weak_b:
            regressions.append(f"Negotiated cipher suite downgraded from {cipher_a} to weak cipher {cipher_b}")
        elif weak_a and not weak_b:
            improvements.append(f"Negotiated cipher suite upgraded from weak cipher {cipher_a} to strong cipher {cipher_b}")

    # Forward Secrecy / Key Exchange
    fs_a = first_profile.get("forward_secrecy")
    fs_b = second_profile.get("forward_secrecy")
    if fs_a is not None and fs_b is not None and fs_a != fs_b:
        if fs_a is True and fs_b is False:
            regressions.append("Forward Secrecy disabled (static key exchange negotiated)")
        elif fs_a is False and fs_b is True:
            improvements.append("Forward Secrecy enabled (ephemeral key exchange negotiated)")

    dh_a = first_profile.get("key_exchange_bits")
    dh_b = second_profile.get("key_exchange_bits")
    if dh_a and dh_b and dh_a != dh_b:
        if dh_a >= 2048 and dh_b < 2048:
            regressions.append(f"Key exchange parameters weakened from {dh_a} to {dh_b} bits")
        elif dh_a < 2048 and dh_b >= 2048:
            improvements.append(f"Key exchange parameters strengthened from {dh_a} to {dh_b} bits")

    # Evaluate specific regression types
    if len(regressions) == 1 and not improvements:
        reg_text = regressions[0]
        if "Protocol downgraded" in reg_text:
            return {
                "classification": PostureEvolutionType.PROTOCOL_DOWNGRADE.value,
                "primary_category": "REGRESSION",
                "is_regression": True,
                "is_improvement": False,
                "is_certificate_only": False,
                "explanation": reg_text,
                "field_differences_count": len(diffs),
            }
        if "cipher suite downgraded" in reg_text:
            return {
                "classification": PostureEvolutionType.CIPHER_DOWNGRADE.value,
                "primary_category": "REGRESSION",
                "is_regression": True,
                "is_improvement": False,
                "is_certificate_only": False,
                "explanation": reg_text,
                "field_differences_count": len(diffs),
            }
        if "Forward Secrecy disabled" in reg_text or "Key exchange parameters weakened" in reg_text:
            return {
                "classification": PostureEvolutionType.KEY_EXCHANGE_DOWNGRADE.value,
                "primary_category": "REGRESSION",
                "is_regression": True,
                "is_improvement": False,
                "is_certificate_only": False,
                "explanation": reg_text,
                "field_differences_count": len(diffs),
            }

    if regressions and not improvements:
        return {
            "classification": PostureEvolutionType.SECURITY_POSTURE_REGRESSION.value,
            "primary_category": "REGRESSION",
            "is_regression": True,
            "is_improvement": False,
            "is_certificate_only": False,
            "explanation": "Multiple security regressions observed: " + "; ".join(regressions),
            "field_differences_count": len(diffs),
        }

    if improvements and not regressions:
        return {
            "classification": PostureEvolutionType.SECURITY_POSTURE_IMPROVEMENT.value,
            "primary_category": "IMPROVEMENT",
            "is_regression": False,
            "is_improvement": True,
            "is_certificate_only": False,
            "explanation": "Cryptographic security posture improved: " + "; ".join(improvements),
            "field_differences_count": len(diffs),
        }

    if regressions and improvements:
        return {
            "classification": PostureEvolutionType.CRYPTOGRAPHIC_CONFIGURATION_CHANGE.value,
            "primary_category": "CONFIGURATION_CHANGE",
            "is_regression": True,
            "is_improvement": True,
            "is_certificate_only": False,
            "explanation": f"Mixed posture modifications: {len(improvements)} improvement(s), {len(regressions)} regression(s).",
            "field_differences_count": len(diffs),
        }

    # Configuration change without clear regression/improvement
    return {
        "classification": PostureEvolutionType.CRYPTOGRAPHIC_CONFIGURATION_CHANGE.value,
        "primary_category": "CONFIGURATION_CHANGE",
        "is_regression": False,
        "is_improvement": False,
        "is_certificate_only": False,
        "explanation": f"Observed {len(diffs)} cryptographic configuration difference(s) without net security degradation.",
        "field_differences_count": len(diffs),
    }
