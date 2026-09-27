"""
EmailSession, StarttlsState, and TlsHandshake Pydantic schemas.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.models.enums import ProtocolType, StarttlsStatus


class StarttlsStateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    observed_state: StarttlsStatus
    advertised_in_frame: Optional[int] = None
    command_in_frame: Optional[int] = None
    response_in_frame: Optional[int] = None
    response_code: Optional[int] = None
    is_downgrade_detected: bool
    state_details_json: Optional[str] = None


class TlsHandshakeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    client_hello_frame: Optional[int] = None
    server_hello_frame: Optional[int] = None
    offered_tls_versions: Optional[str] = None
    negotiated_tls_version: Optional[str] = None
    client_cipher_suites: Optional[str] = None
    negotiated_cipher_suite: Optional[str] = None
    key_exchange_group: Optional[str] = None
    key_exchange_bits: Optional[int] = None
    is_forward_secrecy: Optional[bool] = None
    sni_hostname: Optional[str] = None
    alpn_protocols: Optional[str] = None
    handshake_status: str


class EmailSessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    session_index: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: ProtocolType
    is_tls_implicit: bool
    starttls_state: StarttlsStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    packet_count: int
    bytes_transferred: int
    banner: Optional[str] = None
    hostname: Optional[str] = None
    risk_score: Optional[float] = None
