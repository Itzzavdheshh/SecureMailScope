"""
Certificate & CertificateChain Pydantic schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class CertificateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    certificate_index: int
    is_server_cert: bool
    subject_dn: Optional[str] = None
    issuer_dn: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    public_key_type: Optional[str] = None
    public_key_size_bits: Optional[int] = None
    signature_algorithm: Optional[str] = None
    is_weak_signature: bool
    sha256_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    is_self_signed: bool
    is_valid_at_capture: Optional[bool] = None
    san_domains: Optional[str] = None


class CertificateChainRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    chain_length: int
    is_chain_complete: bool
    validation_status: str
    validation_notes: Optional[str] = None
    root_issuer_dn: Optional[str] = None
    leaf_subject_dn: Optional[str] = None
