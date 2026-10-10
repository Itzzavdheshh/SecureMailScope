"""
SecureMailScope — Realistic Forensic Test Laboratory PCAP Generators
Phase 9 — Production-grade binary PCAP generators reusing tested packet-building primitives.
"""

import struct
import io
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ─── PRIMITIVE PACKET BUILDERS ───────────────────────────────────────────────

def build_raw_pcap(packet_payloads: list) -> bytes:
    """
    Construct a valid in-memory binary PCAP file containing Ethernet/IP/TCP packets.
    """
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet linktype
    pcap_data = bytearray(global_hdr)

    for p in packet_payloads:
        payload = p.get("payload", b"")
        src_ip_bytes = bytes(map(int, p.get("src_ip", "192.168.1.10").split(".")))
        dst_ip_bytes = bytes(map(int, p.get("dst_ip", "198.51.100.25").split(".")))
        src_port = p.get("src_port", 54321)
        dst_port = p.get("dst_port", 25)
        seq = p.get("seq", 100)
        ack = p.get("ack", 1)
        flags = p.get("flags", 0x18)
        ts = p.get("timestamp", 1700000000.0)

        # TCP Header (20 bytes)
        tcp_hdr = struct.pack(">HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | flags, 64240, 0, 0)
        tcp_len = len(tcp_hdr) + len(payload)

        # IP Header (20 bytes)
        ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + tcp_len, 1, 0, 64, 6, 0, src_ip_bytes, dst_ip_bytes)

        # Ethernet Header (14 bytes)
        eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

        full_packet = eth_hdr + ip_hdr + tcp_hdr + payload
        pkt_len = len(full_packet)

        sec = int(ts)
        usec = int((ts - sec) * 1000000)
        pkt_hdr = struct.pack("<IIII", sec, usec, pkt_len, pkt_len)

        pcap_data.extend(pkt_hdr)
        pcap_data.extend(full_packet)

    return bytes(pcap_data)


def generate_cert(
    cn="mail.example.com",
    days_valid=30,
    days_offset=0,
    key_size=2048,
    sig_hash=hashes.SHA256(),
    san_dns=None,
    is_ca=False,
    issuer_cn=None,
):
    """Generate synthetic DER encoded X.509 certificate using cryptography."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Lab"),
    ])
    
    if issuer_cn and issuer_cn != cn:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope CA Authority"),
        ])
    else:
        issuer = subject

    now = datetime.now(timezone.utc)
    not_before = now + timedelta(days=days_offset)
    not_after = not_before + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_dns:
        dns_names = [x509.DNSName(name) for name in san_dns]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False
        )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

    cert = builder.sign(private_key, sig_hash)
    return cert.public_bytes(serialization.Encoding.DER)


def build_raw_client_hello_payload(
    legacy_version=0x0303,
    sni=None,
    alpn=None,
    supported_versions=None,
    cipher_suites=None
):
    """Build a raw TLS ClientHello handshake payload."""
    if cipher_suites is None:
        cipher_suites = [0x1302, 0x1301, 0xC02F, 0x009C]

    cs_bytes = b"".join(struct.pack(">H", cs) for cs in cipher_suites)
    ext_bytes = bytearray()

    if sni:
        sni_b = sni.encode("utf-8")
        sni_ext_data = struct.pack(">H", len(sni_b) + 3) + b"\x00" + struct.pack(">H", len(sni_b)) + sni_b
        ext_bytes.extend(struct.pack(">HH", 0, len(sni_ext_data)) + sni_ext_data)

    if alpn:
        alpn_data = bytearray()
        for p in alpn:
            pb = p.encode("utf-8")
            alpn_data.append(len(pb))
            alpn_data.extend(pb)
        alpn_ext_data = struct.pack(">H", len(alpn_data)) + alpn_data
        ext_bytes.extend(struct.pack(">HH", 16, len(alpn_ext_data)) + alpn_ext_data)

    if supported_versions:
        sv_data = bytearray([len(supported_versions) * 2])
        for v in supported_versions:
            sv_data.extend(struct.pack(">H", v))
        ext_bytes.extend(struct.pack(">HH", 43, len(sv_data)) + sv_data)

    body = bytearray()
    body.extend(struct.pack(">H", legacy_version))
    body.extend(b"\x01" * 32)  # Random
    body.append(0)  # Session ID len 0
    body.extend(struct.pack(">H", len(cs_bytes)))
    body.extend(cs_bytes)
    body.append(1)  # Comp methods len 1
    body.append(0)  # null compression
    body.extend(struct.pack(">H", len(ext_bytes)))
    body.extend(ext_bytes)

    hdr = b"\x01" + struct.pack(">I", len(body))[1:]  # msg_type 1 (ClientHello)
    return bytes(hdr + body)


def build_raw_server_hello_payload(
    legacy_version=0x0303,
    selected_cs=0xC02F,
    supported_versions=None
):
    """Build a raw TLS ServerHello handshake payload."""
    ext_bytes = bytearray()

    if supported_versions:
        sv_data = struct.pack(">H", supported_versions[0])
        ext_bytes.extend(struct.pack(">HH", 43, len(sv_data)) + sv_data)

    body = bytearray()
    body.extend(struct.pack(">H", legacy_version))
    body.extend(b"\x02" * 32)  # Random
    body.append(0)  # Session ID len 0
    body.extend(struct.pack(">H", selected_cs))
    body.append(0)  # null compression
    body.extend(struct.pack(">H", len(ext_bytes)))
    body.extend(ext_bytes)

    hdr = b"\x02" + struct.pack(">I", len(body))[1:]  # msg_type 2 (ServerHello)
    return bytes(hdr + body)


def build_raw_certificate_payload(der_certs):
    """Build a raw TLS Certificate handshake payload (msg_type 11)."""
    certs_data = bytearray()
    for der in der_certs:
        certs_data.extend(struct.pack(">I", len(der))[1:])  # 3-byte cert len
        certs_data.extend(der)

    body = struct.pack(">I", len(certs_data))[1:] + certs_data
    hdr = b"\x0b" + struct.pack(">I", len(body))[1:]
    return bytes(hdr + body)


def wrap_in_tls_record(payload, content_type=22, version=0x0303):
    """Wrap handshake payload in 5-byte TLS record header."""
    hdr = struct.pack(">BHH", content_type, version, len(payload))
    return hdr + payload


# ─── SCENARIO GENERATORS ─────────────────────────────────────────────────────

def generate_scenario_a() -> bytes:
    """Scenario A: Secure SMTP — TLS 1.3, AES-256-GCM, valid cert with SAN."""
    cert_der = generate_cert(cn="mail.secure.example", days_valid=90, san_dns=["mail.secure.example", "smtp.secure.example"], issuer_cn="SecureMailScope CA Authority")
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mail.secure.example", alpn=["smtp"], supported_versions=[0x0304, 0x0303]))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0x1302, supported_versions=[0x0304])) # TLS 1.3
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.50", "src_port": 50001, "dst_ip": "198.51.100.10", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mail.secure.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.50", "src_port": 50001, "dst_ip": "198.51.100.10", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.10", "src_port": 25, "dst_ip": "10.0.1.50", "dst_port": 50001, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.50", "src_port": 50001, "dst_ip": "198.51.100.10", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.10", "src_port": 25, "dst_ip": "10.0.1.50", "dst_port": 50001, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_b() -> bytes:
    """Scenario B: Deprecated TLS Version — TLS 1.0 Negotiated."""
    cert_der = generate_cert(cn="smtp.legacy.example", days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="smtp.legacy.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0301, selected_cs=0x0035)) # TLS 1.0
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.51", "src_port": 50002, "dst_ip": "198.51.100.11", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 smtp.legacy.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.51", "src_port": 50002, "dst_ip": "198.51.100.11", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.11", "src_port": 25, "dst_ip": "10.0.1.51", "dst_port": 50002, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.51", "src_port": 50002, "dst_ip": "198.51.100.11", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.11", "src_port": 25, "dst_ip": "10.0.1.51", "dst_port": 50002, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_c() -> bytes:
    """Scenario C: Weak Cipher Suite — RC4 Negotiated."""
    cert_der = generate_cert(cn="smtp.weakcipher.example", days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="smtp.weakcipher.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0x0005)) # TLS_RSA_WITH_RC4_128_SHA
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.52", "src_port": 50003, "dst_ip": "198.51.100.12", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 smtp.weakcipher.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.52", "src_port": 50003, "dst_ip": "198.51.100.12", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.12", "src_port": 25, "dst_ip": "10.0.1.52", "dst_port": 50003, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.52", "src_port": 50003, "dst_ip": "198.51.100.12", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.12", "src_port": 25, "dst_ip": "10.0.1.52", "dst_port": 50003, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_d() -> bytes:
    """Scenario D: Self-Signed Certificate."""
    cert_der = generate_cert(cn="mail.selfsigned.example", days_valid=90) # subject == issuer
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mail.selfsigned.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0xC02F))
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.53", "src_port": 50004, "dst_ip": "198.51.100.13", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mail.selfsigned.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.53", "src_port": 50004, "dst_ip": "198.51.100.13", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.13", "src_port": 25, "dst_ip": "10.0.1.53", "dst_port": 50004, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.53", "src_port": 50004, "dst_ip": "198.51.100.13", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.13", "src_port": 25, "dst_ip": "10.0.1.53", "dst_port": 50004, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_e() -> bytes:
    """Scenario E: Expired Certificate at Capture Time."""
    # Certificate expired 20 days ago relative to NOW (not_before=-30d, not_after=-20d).
    # Capture timestamp = now, so cert is expired at capture time -> triggers CERT-001.
    cert_der = generate_cert(cn="mail.expired.example", days_valid=10, days_offset=-30)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mail.expired.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0xC02F))
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()  # Capture at NOW: cert expired 20 days ago -> is_valid_at_capture=False
    return build_raw_pcap([
        {"src_ip": "10.0.1.54", "src_port": 50005, "dst_ip": "198.51.100.14", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mail.expired.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.54", "src_port": 50005, "dst_ip": "198.51.100.14", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.14", "src_port": 25, "dst_ip": "10.0.1.54", "dst_port": 50005, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.54", "src_port": 50005, "dst_ip": "198.51.100.14", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.14", "src_port": 25, "dst_ip": "10.0.1.54", "dst_port": 50005, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_f() -> bytes:
    """Scenario F: No Forward Secrecy — Static RSA Key Exchange."""
    cert_der = generate_cert(cn="mail.staticrsa.example", days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mail.staticrsa.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0x0035)) # TLS_RSA_WITH_AES_128_CBC_SHA
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.55", "src_port": 50006, "dst_ip": "198.51.100.15", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mail.staticrsa.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.55", "src_port": 50006, "dst_ip": "198.51.100.15", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.15", "src_port": 25, "dst_ip": "10.0.1.55", "dst_port": 50006, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.55", "src_port": 50006, "dst_ip": "198.51.100.15", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.15", "src_port": 25, "dst_ip": "10.0.1.55", "dst_port": 50006, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_g() -> bytes:
    """Scenario G: STARTTLS Rejected / Security Failure."""
    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.56", "src_port": 50007, "dst_ip": "198.51.100.16", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mail.reject.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.56", "src_port": 50007, "dst_ip": "198.51.100.16", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.16", "src_port": 25, "dst_ip": "10.0.1.56", "dst_port": 50007, "seq": 40, "timestamp": ts + 0.2, "payload": b"454 4.7.0 TLS not available due to local problem\r\n"},
    ])


def generate_scenario_h() -> bytes:
    """Scenario H: Incomplete / Truncated Evidence (ClientHello with no ServerHello)."""
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mail.truncated.example"))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.1.57", "src_port": 50008, "dst_ip": "198.51.100.17", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mail.truncated.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.1.57", "src_port": 50008, "dst_ip": "198.51.100.17", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.17", "src_port": 25, "dst_ip": "10.0.1.57", "dst_port": 50008, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.1.57", "src_port": 50008, "dst_ip": "198.51.100.17", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
    ])


def generate_scenario_i() -> bytes:
    """Scenario I: Multi-Session SMTP (3 distinct sessions in 1 PCAP)."""
    cert1 = generate_cert(cn="mx1.multi.example", days_valid=90, san_dns=["mx1.multi.example"])
    cert2 = generate_cert(cn="mx2.multi.example", days_valid=90)

    ch1 = wrap_in_tls_record(build_raw_client_hello_payload(sni="mx1.multi.example", supported_versions=[0x0304]))
    sh1 = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0x1302, supported_versions=[0x0304]))
    cm1 = wrap_in_tls_record(build_raw_certificate_payload([cert1]))

    ch2 = wrap_in_tls_record(build_raw_client_hello_payload(sni="mx2.multi.example"))
    sh2 = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0301, selected_cs=0x0035)) # TLS 1.0
    cm2 = wrap_in_tls_record(build_raw_certificate_payload([cert2]))

    ts = time.time()
    pkts = [
        # Session 1: Client 10.0.2.1:60001 -> Server 198.51.100.21:25 (Secure TLS 1.3)
        {"src_ip": "10.0.2.1", "src_port": 60001, "dst_ip": "198.51.100.21", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mx1.multi.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.2.1", "src_port": 60001, "dst_ip": "198.51.100.21", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.21", "src_port": 25, "dst_ip": "10.0.2.1", "dst_port": 60001, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.2.1", "src_port": 60001, "dst_ip": "198.51.100.21", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch1},
        {"src_ip": "198.51.100.21", "src_port": 25, "dst_ip": "10.0.2.1", "dst_port": 60001, "seq": 70, "timestamp": ts + 0.4, "payload": sh1 + cm1},

        # Session 2: Client 10.0.2.1:60002 -> Server 198.51.100.21:25 (Deprecated TLS 1.0)
        {"src_ip": "10.0.2.1", "src_port": 60002, "dst_ip": "198.51.100.21", "dst_port": 25, "seq": 1, "timestamp": ts + 10.0, "payload": b"220 mx1.multi.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.2.1", "src_port": 60002, "dst_ip": "198.51.100.21", "dst_port": 25, "seq": 1, "timestamp": ts + 10.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.21", "src_port": 25, "dst_ip": "10.0.2.1", "dst_port": 60002, "seq": 40, "timestamp": ts + 10.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.2.1", "src_port": 60002, "dst_ip": "198.51.100.21", "dst_port": 25, "seq": 11, "timestamp": ts + 10.3, "payload": ch2},
        {"src_ip": "198.51.100.21", "src_port": 25, "dst_ip": "10.0.2.1", "dst_port": 60002, "seq": 70, "timestamp": ts + 10.4, "payload": sh2 + cm2},

        # Session 3: Client 10.0.2.2:60003 -> Server 198.51.100.22:25 (STARTTLS Rejected)
        {"src_ip": "10.0.2.2", "src_port": 60003, "dst_ip": "198.51.100.22", "dst_port": 25, "seq": 1, "timestamp": ts + 20.0, "payload": b"220 mx2.multi.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.2.2", "src_port": 60003, "dst_ip": "198.51.100.22", "dst_port": 25, "seq": 1, "timestamp": ts + 20.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.22", "src_port": 25, "dst_ip": "10.0.2.2", "dst_port": 60003, "seq": 40, "timestamp": ts + 20.2, "payload": b"454 4.7.0 TLS temporary failure\r\n"},
    ]
    return build_raw_pcap(pkts)


def generate_scenario_j1(variant: int = 0) -> bytes:
    """
    Scenario J1: Baseline Capture — Server 198.51.100.30:25 Negotiating TLS 1.3.
    `variant` (0, 1, 2, ...) varies the client source port so that repeated
    baseline uploads produce unique PCAP bytes with unique SHA-256 hashes,
    bypassing the 409 duplicate dedup guard.
    """
    cert_der = generate_cert(cn="mx.drift.example", days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mx.drift.example", supported_versions=[0x0304]))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0x1302, supported_versions=[0x0304]))
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    client_port = 55001 + variant  # unique port per variant -> unique PCAP bytes
    ts = time.time() + variant  # also vary timestamp to avoid any edge-case collision
    return build_raw_pcap([
        {"src_ip": "10.0.3.1", "src_port": client_port, "dst_ip": "198.51.100.30", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mx.drift.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.3.1", "src_port": client_port, "dst_ip": "198.51.100.30", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.30", "src_port": 25, "dst_ip": "10.0.3.1", "dst_port": client_port, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.3.1", "src_port": client_port, "dst_ip": "198.51.100.30", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.30", "src_port": 25, "dst_ip": "10.0.3.1", "dst_port": client_port, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_j2() -> bytes:
    """Scenario J2: Drift Capture — Server 198.51.100.30:25 Downgraded to TLS 1.0."""
    cert_der = generate_cert(cn="mx.drift.example", days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mx.drift.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0301, selected_cs=0x0035)) # Downgraded to TLS 1.0!
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_der]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.3.2", "src_port": 55002, "dst_ip": "198.51.100.30", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mx.drift.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.3.2", "src_port": 55002, "dst_ip": "198.51.100.30", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.30", "src_port": 25, "dst_ip": "10.0.3.2", "dst_port": 55002, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.3.2", "src_port": 55002, "dst_ip": "198.51.100.30", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.30", "src_port": 25, "dst_ip": "10.0.3.2", "dst_port": 55002, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_k1() -> bytes:
    """Scenario K1: Certificate Rotation Initial — Server 198.51.100.40:25 with Cert A."""
    cert_a = generate_cert(cn="mx.rotation.example", key_size=2048, days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mx.rotation.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0xC02F))
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_a]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.4.1", "src_port": 56001, "dst_ip": "198.51.100.40", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mx.rotation.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.4.1", "src_port": 56001, "dst_ip": "198.51.100.40", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.40", "src_port": 25, "dst_ip": "10.0.4.1", "dst_port": 56001, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.4.1", "src_port": 56001, "dst_ip": "198.51.100.40", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.40", "src_port": 25, "dst_ip": "10.0.4.1", "dst_port": 56001, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])


def generate_scenario_k2() -> bytes:
    """Scenario K2: Certificate Rotation New — Server 198.51.100.40:25 with Cert B."""
    # Different serial & key size (3072-bit RSA) -> different SHA-256 fingerprint!
    cert_b = generate_cert(cn="mx.rotation.example", key_size=3072, days_valid=90)
    ch_raw = wrap_in_tls_record(build_raw_client_hello_payload(sni="mx.rotation.example"))
    sh_raw = wrap_in_tls_record(build_raw_server_hello_payload(legacy_version=0x0303, selected_cs=0xC02F))
    cm_raw = wrap_in_tls_record(build_raw_certificate_payload([cert_b]))

    ts = time.time()
    return build_raw_pcap([
        {"src_ip": "10.0.4.2", "src_port": 56002, "dst_ip": "198.51.100.40", "dst_port": 25, "seq": 1, "timestamp": ts + 0.0, "payload": b"220 mx.rotation.example ESMTP\r\n250-STARTTLS\r\n"},
        {"src_ip": "10.0.4.2", "src_port": 56002, "dst_ip": "198.51.100.40", "dst_port": 25, "seq": 1, "timestamp": ts + 0.1, "payload": b"STARTTLS\r\n"},
        {"src_ip": "198.51.100.40", "src_port": 25, "dst_ip": "10.0.4.2", "dst_port": 56002, "seq": 40, "timestamp": ts + 0.2, "payload": b"220 2.0.0 Ready to start TLS\r\n"},
        {"src_ip": "10.0.4.2", "src_port": 56002, "dst_ip": "198.51.100.40", "dst_port": 25, "seq": 11, "timestamp": ts + 0.3, "payload": ch_raw},
        {"src_ip": "198.51.100.40", "src_port": 25, "dst_ip": "10.0.4.2", "dst_port": 56002, "seq": 70, "timestamp": ts + 0.4, "payload": sh_raw + cm_raw},
    ])
