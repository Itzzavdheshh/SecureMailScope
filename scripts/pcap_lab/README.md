# SecureMailScope — Realistic Forensic Test Laboratory

Welcome to the **SecureMailScope Realistic Forensic Test Laboratory** (Phase 9).

This test laboratory provides production-grade, deterministic binary PCAP generation and scenario coverage to exercise the complete SecureMailScope forensic pipeline:

$$\text{PCAP} \longrightarrow \text{PCAP Reader} \longrightarrow \text{TCP Reassembly} \longrightarrow \text{Protocol Detection} \longrightarrow \text{STARTTLS State Machine} \longrightarrow \text{TLS Parser} \longrightarrow \text{X.509 Analyzer} \longrightarrow \text{Rule Engine} \longrightarrow \text{Risk Engine} \longrightarrow \text{Evidence} \longrightarrow \text{Infrastructure Identity} \longrightarrow \text{Baseline/Drift} \longrightarrow \text{Timeline} \longrightarrow \text{REST API} \longrightarrow \text{Frontend}$$

---

## Lab Scenario Matrix

| ID | Scenario Name | Protocol | Expected STARTTLS | Expected TLS | Key Finding / Feature Demonstrated |
|---|---|---|---|---|---|
| **1** | Secure SMTP | SMTP | ACCEPTED | TLS 1.3 | Genuinely observed secure configuration (`TLS_AES_256_GCM_SHA384`, valid SAN cert) |
| **2** | Deprecated TLS Version | SMTP | ACCEPTED | TLS 1.0 | `CRYPT-001` (Deprecated TLS 1.0 negotiated) |
| **3** | Weak Cipher Suite | SMTP | ACCEPTED | TLS 1.2 | `CRYPT-005` (RC4 stream cipher negotiated) |
| **4** | Self-Signed Certificate | SMTP | ACCEPTED | TLS 1.2 | `CERT-005` (Self-signed X.509 certificate) |
| **5** | Expired Certificate | SMTP | ACCEPTED | TLS 1.2 | `CERT-001` (Certificate expired at capture time) |
| **6** | No Forward Secrecy | SMTP | ACCEPTED | TLS 1.2 | `CRYPT-004` (Static RSA key exchange, no DHE/ECDHE) |
| **7** | STARTTLS Rejected | SMTP | REJECTED | None | `STLS-002` (Explicit STARTTLS rejection response code 454) |
| **8** | Truncated Handshake | SMTP | ACCEPTED | None | `INSUFFICIENT_EVIDENCE` handling on incomplete ClientHello |
| **9** | Multi-Session SMTP | SMTP | MIXED | MIXED | Reconstructs 3 distinct TCP sessions in 1 PCAP file |
| **10a**| Baseline Capture | SMTP | ACCEPTED | TLS 1.3 | Establishes initial secure baseline profile for `198.51.100.30` |
| **10b**| Drift Capture | SMTP | ACCEPTED | TLS 1.0 | Detects `TLS_VERSION_DOWNGRADED` drift event against baseline |
| **11a**| Cert Rotation Initial | SMTP | ACCEPTED | TLS 1.2 | Establishes baseline profile with Certificate A (2048-bit RSA) |
| **11b**| Cert Rotation New | SMTP | ACCEPTED | TLS 1.2 | Proves host identity stability (`198.51.100.40:25:SMTP`) during cert update |

---

## CLI Usage

Generate scenario PCAPs from the repository root:

```bash
# List all available scenario descriptions and status
python scripts/generate_pcap.py --list

# Generate a single scenario (e.g., Scenario 1)
python scripts/generate_pcap.py --scenario 1 --output ./pcaps/scenario_01.pcap

# Generate all scenarios into an output directory
python scripts/generate_pcap.py --all --output-dir ./pcaps/
```

---

## Verification & Automated Testing

Run the Phase 9 scenario test suite:

```bash
backend/venv/Scripts/python.exe -m pytest backend/tests/test_phase9_scenarios.py -v
```
