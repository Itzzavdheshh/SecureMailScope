"""
Domain Enums for SecureMailScope.
Used across database models, Pydantic schemas, and analysis logic.
"""

from enum import Enum


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ProtocolType(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class StarttlsStatus(str, Enum):
    NOT_OBSERVED = "NOT_OBSERVED"
    ADVERTISED = "ADVERTISED"
    ATTEMPTED = "ATTEMPTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    ANOMALOUS = "ANOMALOUS"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceStatus(str, Enum):
    """
    Forensic evidence evaluation status.
    Mandatory explicitly tracked states — no guessed or implicit values.
    """
    OBSERVED = "OBSERVED"
    ANALYZED = "ANALYZED"
    INFERRED = "INFERRED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class FindingCategory(str, Enum):
    TLS_CRYPTO = "TLS_CRYPTO"
    X509_CERT = "X509_CERT"
    STARTTLS = "STARTTLS"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"


class RiskBand(str, Enum):
    CRITICAL = "CRITICAL"   # 80.0 - 100.0
    HIGH = "HIGH"           # 60.0 - 79.9
    MEDIUM = "MEDIUM"       # 40.0 - 59.9
    LOW = "LOW"             # 20.0 - 39.9
    SECURE = "SECURE"       # 0.0 - 19.9


class DriftEventType(str, Enum):
    CIPHER_DOWNGRADE = "CIPHER_DOWNGRADE"
    TLS_VERSION_DOWNGRADE = "TLS_VERSION_DOWNGRADE"
    CERT_EXPIRED = "CERT_EXPIRED"
    CERT_CHANGED = "CERT_CHANGED"
    STARTTLS_DISABLED = "STARTTLS_DISABLED"
    RISK_SCORE_INCREASED = "RISK_SCORE_INCREASED"
