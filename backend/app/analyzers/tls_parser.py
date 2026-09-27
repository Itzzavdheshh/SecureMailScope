"""
TLS Record Layer & Handshake Dissection Analyzer.
Performs manual and hybrid parsing of TLS record layers (ClientHello, ServerHello, Certificate).
Extracts offered/negotiated TLS versions, cipher suites, SNI, ALPN, key exchange attributes,
and computes JA3 / JA3S fingerprints.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

# GREASE values to ignore during JA3/JA3S fingerprinting
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}

# Cipher Suite Registry & Mapping
CIPHER_SUITES_DB: Dict[int, Dict[str, Any]] = {
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "kex": "RSA_STATIC", "fs": False, "family": "RC4"},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "kex": "RSA_STATIC", "fs": False, "family": "RC4"},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kex": "RSA_STATIC", "fs": False, "family": "3DES"},
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "kex": "RSA_STATIC", "fs": False, "family": "AES-CBC"},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "kex": "RSA_STATIC", "fs": False, "family": "AES-CBC"},
    0x0067: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kex": "DHE", "fs": True, "family": "AES-GCM"},
    0x006B: {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "kex": "DHE", "fs": True, "family": "AES-GCM"},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "kex": "RSA_STATIC", "fs": False, "family": "AES-GCM"},
    0x009D: {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "kex": "RSA_STATIC", "fs": False, "family": "AES-GCM"},
    0xC013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "kex": "ECDHE", "fs": True, "family": "AES-CBC"},
    0xC014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "kex": "ECDHE", "fs": True, "family": "AES-CBC"},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex": "ECDHE", "fs": True, "family": "AES-GCM"},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kex": "ECDHE", "fs": True, "family": "AES-GCM"},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "kex": "ECDHE", "fs": True, "family": "ChaCha20-Poly1305"},
    0xCCA9: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "kex": "ECDHE", "fs": True, "family": "ChaCha20-Poly1305"},
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "kex": "TLS13_EPHEMERAL", "fs": True, "family": "AES-GCM"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA256", "kex": "TLS13_EPHEMERAL", "fs": True, "family": "AES-GCM"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "kex": "TLS13_EPHEMERAL", "fs": True, "family": "ChaCha20-Poly1305"},
}

TLS_VERSION_NAMES = {
    0x0200: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def normalize_tls_version(version_code: int) -> str:
    """Map numeric TLS version code to standardized string name."""
    return TLS_VERSION_NAMES.get(version_code, f"UNKNOWN (0x{version_code:04x})")


@dataclass
class ClientHelloParsed:
    frame_number: int
    timestamp: float
    legacy_version: int
    legacy_version_name: str
    client_random: bytes
    session_id: bytes
    cipher_suites: List[int]
    compression_methods: List[int]
    extensions: Dict[int, bytes]
    sni_hostname: Optional[str] = None
    alpn_protocols: List[str] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    ja3_str: Optional[str] = None
    ja3_hash: Optional[str] = None
    raw_bytes: bytes = b""


@dataclass
class ServerHelloParsed:
    frame_number: int
    timestamp: float
    legacy_version: int
    legacy_version_name: str
    server_random: bytes
    session_id: bytes
    selected_cipher_suite: int
    cipher_name: str
    key_exchange: str
    is_forward_secrecy: Optional[bool]
    negotiated_tls_version: str
    extensions: Dict[int, bytes]
    supported_versions: List[int] = field(default_factory=list)
    ja3s_str: Optional[str] = None
    ja3s_hash: Optional[str] = None
    raw_bytes: bytes = b""


@dataclass
class TlsCertificateParsed:
    frame_number: int
    timestamp: float
    der_certificates: List[bytes]
    raw_bytes: bytes = b""


@dataclass
class TlsRecord:
    content_type: int
    version: int
    length: int
    payload: bytes
    frame_number: int
    timestamp: float


def parse_tls_records(payload: bytes, frame_number: int = 0, timestamp: float = 0.0) -> List[TlsRecord]:
    """
    Parse zero or more TLS records from raw application layer bytes.
    Robust against truncated/malformed buffers.
    """
    records: List[TlsRecord] = []
    idx = 0
    buf_len = len(payload)

    while idx + 5 <= buf_len:
        content_type = payload[idx]
        # Valid TLS content types: 20 (CCS), 21 (Alert), 22 (Handshake), 23 (AppData)
        if content_type not in (20, 21, 22, 23):
            idx += 1
            continue

        ver_major = payload[idx + 1]
        ver_minor = payload[idx + 2]
        # Legacy version usually 0x03, 0x00 to 0x04
        if ver_major != 3 and not (content_type == 22 and ver_major == 2):
            idx += 1
            continue

        version = (ver_major << 8) | ver_minor
        rec_len = struct.unpack(">H", payload[idx + 3:idx + 5])[0]

        if idx + 5 + rec_len > buf_len:
            # Truncated record — stop processing remaining payload
            break

        rec_payload = payload[idx + 5:idx + 5 + rec_len]
        records.append(TlsRecord(
            content_type=content_type,
            version=version,
            length=rec_len,
            payload=rec_payload,
            frame_number=frame_number,
            timestamp=timestamp,
        ))
        idx += 5 + rec_len

    return records


def parse_client_hello(payload: bytes, frame_number: int = 0, timestamp: float = 0.0) -> Optional[ClientHelloParsed]:
    """
    Parse a TLS ClientHello handshake message payload (excluding 5-byte record header).
    Handshake structure:
    - 1 byte msg_type (1 = ClientHello)
    - 3 bytes length
    - 2 bytes legacy_version
    - 32 bytes random
    - 1 byte session_id length + session_id
    - 2 bytes cipher_suites length + cipher_suites
    - 1 byte compression_methods length + compression_methods
    - 2 bytes extensions length + extensions
    """
    try:
        if len(payload) < 38:
            return None

        idx = 0
        msg_type = payload[idx]
        if msg_type != 1:  # ClientHello
            return None

        msg_len = struct.unpack(">I", b"\x00" + payload[idx + 1:idx + 4])[0]
        idx += 4

        if idx + 34 > len(payload):
            return None

        legacy_version = struct.unpack(">H", payload[idx:idx + 2])[0]
        idx += 2

        client_random = payload[idx:idx + 32]
        idx += 32

        # Session ID
        sess_id_len = payload[idx]
        idx += 1
        if idx + sess_id_len > len(payload):
            return None
        session_id = payload[idx:idx + sess_id_len]
        idx += sess_id_len

        # Cipher Suites
        if idx + 2 > len(payload):
            return None
        cs_len = struct.unpack(">H", payload[idx:idx + 2])[0]
        idx += 2
        if idx + cs_len > len(payload):
            return None

        cipher_suites = []
        for i in range(0, cs_len, 2):
            cs_val = struct.unpack(">H", payload[idx + i:idx + i + 2])[0]
            cipher_suites.append(cs_val)
        idx += cs_len

        # Compression Methods
        if idx + 1 > len(payload):
            return None
        comp_len = payload[idx]
        idx += 1
        if idx + comp_len > len(payload):
            return None
        compression_methods = list(payload[idx:idx + comp_len])
        idx += comp_len

        # Extensions
        extensions: Dict[int, bytes] = {}
        sni_hostname = None
        alpn_protocols: List[str] = []
        supported_versions: List[int] = []
        supported_groups: List[int] = []
        signature_algorithms: List[int] = []
        ec_point_formats: List[int] = []

        if idx + 2 <= len(payload):
            ext_total_len = struct.unpack(">H", payload[idx:idx + 2])[0]
            idx += 2
            ext_end = min(idx + ext_total_len, len(payload))

            while idx + 4 <= ext_end:
                ext_type = struct.unpack(">H", payload[idx:idx + 2])[0]
                ext_len = struct.unpack(">H", payload[idx + 2:idx + 4])[0]
                idx += 4
                if idx + ext_len > ext_end:
                    break

                ext_data = payload[idx:idx + ext_len]
                extensions[ext_type] = ext_data
                idx += ext_len

                # Parse specific extension types
                if ext_type == 0:  # SNI
                    if len(ext_data) >= 5:
                        list_len = struct.unpack(">H", ext_data[0:2])[0]
                        if list_len + 2 <= len(ext_data) and ext_data[2] == 0:  # host_name name_type
                            name_len = struct.unpack(">H", ext_data[3:5])[0]
                            if 5 + name_len <= len(ext_data):
                                sni_hostname = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")

                elif ext_type == 16:  # ALPN
                    if len(ext_data) >= 2:
                        alpn_list_len = struct.unpack(">H", ext_data[0:2])[0]
                        alpn_idx = 2
                        while alpn_idx < len(ext_data):
                            proto_len = ext_data[alpn_idx]
                            alpn_idx += 1
                            if alpn_idx + proto_len <= len(ext_data):
                                proto_str = ext_data[alpn_idx:alpn_idx + proto_len].decode("utf-8", errors="ignore")
                                alpn_protocols.append(proto_str)
                                alpn_idx += proto_len
                            else:
                                break

                elif ext_type == 43:  # supported_versions (0x002b)
                    if len(ext_data) >= 1:
                        sv_len = ext_data[0]
                        for sv_i in range(1, min(1 + sv_len, len(ext_data)), 2):
                            if sv_i + 2 <= len(ext_data):
                                sv_val = struct.unpack(">H", ext_data[sv_i:sv_i + 2])[0]
                                supported_versions.append(sv_val)

                elif ext_type == 10:  # supported_groups (0x000a)
                    if len(ext_data) >= 2:
                        sg_len = struct.unpack(">H", ext_data[0:2])[0]
                        for sg_i in range(2, min(2 + sg_len, len(ext_data)), 2):
                            if sg_i + 2 <= len(ext_data):
                                sg_val = struct.unpack(">H", ext_data[sg_i:sg_i + 2])[0]
                                supported_groups.append(sg_val)

                elif ext_type == 13:  # signature_algorithms (0x000d)
                    if len(ext_data) >= 2:
                        sa_len = struct.unpack(">H", ext_data[0:2])[0]
                        for sa_i in range(2, min(2 + sa_len, len(ext_data)), 2):
                            if sa_i + 2 <= len(ext_data):
                                sa_val = struct.unpack(">H", ext_data[sa_i:sa_i + 2])[0]
                                signature_algorithms.append(sa_val)

                elif ext_type == 11:  # ec_point_formats (0x000b)
                    if len(ext_data) >= 1:
                        pf_len = ext_data[0]
                        ec_point_formats = list(ext_data[1:1 + pf_len])

        # Compute JA3 fingerprint
        # JA3 = SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_cs = [str(c) for c in cipher_suites if c not in GREASE_VALUES]
        ja3_ext = [str(e) for e in extensions.keys() if e not in GREASE_VALUES]
        ja3_groups = [str(g) for g in supported_groups if g not in GREASE_VALUES]
        ja3_pf = [str(p) for p in ec_point_formats]

        ja3_str = f"{legacy_version},{'-'.join(ja3_cs)},{'-'.join(ja3_ext)},{'-'.join(ja3_groups)},{'-'.join(ja3_pf)}"
        ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

        return ClientHelloParsed(
            frame_number=frame_number,
            timestamp=timestamp,
            legacy_version=legacy_version,
            legacy_version_name=normalize_tls_version(legacy_version),
            client_random=client_random,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=compression_methods,
            extensions=extensions,
            sni_hostname=sni_hostname,
            alpn_protocols=alpn_protocols,
            supported_versions=supported_versions,
            supported_groups=supported_groups,
            signature_algorithms=signature_algorithms,
            ec_point_formats=ec_point_formats,
            ja3_str=ja3_str,
            ja3_hash=ja3_hash,
            raw_bytes=payload[:msg_len + 4],
        )

    except Exception:
        return None


def parse_server_hello(payload: bytes, frame_number: int = 0, timestamp: float = 0.0) -> Optional[ServerHelloParsed]:
    """
    Parse a TLS ServerHello handshake message payload (excluding 5-byte record header).
    Handshake structure:
    - 1 byte msg_type (2 = ServerHello)
    - 3 bytes length
    - 2 bytes legacy_version
    - 32 bytes random
    - 1 byte session_id length + session_id
    - 2 bytes cipher_suite
    - 1 byte compression_method
    - 2 bytes extensions length + extensions
    """
    try:
        if len(payload) < 38:
            return None

        idx = 0
        msg_type = payload[idx]
        if msg_type != 2:  # ServerHello
            return None

        msg_len = struct.unpack(">I", b"\x00" + payload[idx + 1:idx + 4])[0]
        idx += 4

        if idx + 34 > len(payload):
            return None

        legacy_version = struct.unpack(">H", payload[idx:idx + 2])[0]
        idx += 2

        server_random = payload[idx:idx + 32]
        idx += 32

        # Session ID
        sess_id_len = payload[idx]
        idx += 1
        if idx + sess_id_len > len(payload):
            return None
        session_id = payload[idx:idx + sess_id_len]
        idx += sess_id_len

        # Selected Cipher Suite
        if idx + 2 > len(payload):
            return None
        selected_cs = struct.unpack(">H", payload[idx:idx + 2])[0]
        idx += 2

        # Compression Method
        if idx + 1 > len(payload):
            return None
        comp_method = payload[idx]
        idx += 1

        # Extensions
        extensions: Dict[int, bytes] = {}
        supported_versions: List[int] = []

        if idx + 2 <= len(payload):
            ext_total_len = struct.unpack(">H", payload[idx:idx + 2])[0]
            idx += 2
            ext_end = min(idx + ext_total_len, len(payload))

            while idx + 4 <= ext_end:
                ext_type = struct.unpack(">H", payload[idx:idx + 2])[0]
                ext_len = struct.unpack(">H", payload[idx + 2:idx + 4])[0]
                idx += 4
                if idx + ext_len > ext_end:
                    break

                ext_data = payload[idx:idx + ext_len]
                extensions[ext_type] = ext_data
                idx += ext_len

                if ext_type == 43:  # supported_versions (0x002b)
                    if len(ext_data) >= 2:
                        sv_val = struct.unpack(">H", ext_data[0:2])[0]
                        supported_versions.append(sv_val)

        # Negotiated TLS Version determination
        # TLS 1.3: ServerHello supported_versions extension contains 0x0304
        if 0x0304 in supported_versions:
            negotiated_version = "TLS 1.3"
        else:
            negotiated_version = normalize_tls_version(legacy_version)

        # Cipher Suite Attributes Lookup
        cs_info = CIPHER_SUITES_DB.get(selected_cs, {})
        cipher_name = cs_info.get("name", f"0x{selected_cs:04x}")
        key_exchange = cs_info.get("kex", "UNKNOWN")
        is_forward_secrecy = cs_info.get("fs", None)

        if negotiated_version == "TLS 1.3":
            # TLS 1.3 key exchange is always ephemeral (FS = True)
            key_exchange = "TLS13_EPHEMERAL"
            is_forward_secrecy = True

        # JA3S fingerprinting: SSLVersion,CipherSuite,Extensions
        ja3s_ext = [str(e) for e in extensions.keys() if e not in GREASE_VALUES]
        ja3s_str = f"{legacy_version},{selected_cs},{'-'.join(ja3s_ext)}"
        ja3s_hash = hashlib.md5(ja3s_str.encode("ascii")).hexdigest()

        return ServerHelloParsed(
            frame_number=frame_number,
            timestamp=timestamp,
            legacy_version=legacy_version,
            legacy_version_name=normalize_tls_version(legacy_version),
            server_random=server_random,
            session_id=session_id,
            selected_cipher_suite=selected_cs,
            cipher_name=cipher_name,
            key_exchange=key_exchange,
            is_forward_secrecy=is_forward_secrecy,
            negotiated_tls_version=negotiated_version,
            extensions=extensions,
            supported_versions=supported_versions,
            ja3s_str=ja3s_str,
            ja3s_hash=ja3s_hash,
            raw_bytes=payload[:msg_len + 4],
        )

    except Exception:
        return None


def parse_certificate_msg(payload: bytes, frame_number: int = 0, timestamp: float = 0.0) -> Optional[TlsCertificateParsed]:
    """
    Parse a TLS Certificate handshake message (msg_type = 11).
    Extracts DER encoded X.509 certificate bytes.
    """
    try:
        if len(payload) < 7:
            return None

        idx = 0
        msg_type = payload[idx]
        if msg_type != 11:  # Certificate
            return None

        msg_len = struct.unpack(">I", b"\x00" + payload[idx + 1:idx + 4])[0]
        idx += 4

        if idx + 3 > len(payload):
            return None

        certs_len = struct.unpack(">I", b"\x00" + payload[idx:idx + 3])[0]
        idx += 3

        der_certs: List[bytes] = []
        end_idx = min(idx + certs_len, len(payload))

        while idx + 3 <= end_idx:
            cert_len = struct.unpack(">I", b"\x00" + payload[idx:idx + 3])[0]
            idx += 3
            if idx + cert_len > end_idx:
                break
            cert_der = payload[idx:idx + cert_len]
            der_certs.append(cert_der)
            idx += cert_len

        return TlsCertificateParsed(
            frame_number=frame_number,
            timestamp=timestamp,
            der_certificates=der_certs,
            raw_bytes=payload[:msg_len + 4],
        )

    except Exception:
        return None
