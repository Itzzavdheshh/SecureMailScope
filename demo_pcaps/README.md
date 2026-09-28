# SecureMailScope Demo PCAP Laboratory

Welcome to the **SecureMailScope Forensic Test Laboratory**. This directory contains 10 verified, production-grade network capture (`.pcap`) files generated using real binary packet builders.

These scenarios allow non-technical analysts and evaluators to manually test every aspect of the **SecureMailScope** forensic analysis workbench—from protocol identification and STARTTLS negotiation tracking to deterministic security rule evaluation, baseline posture drift detection, and behavioral AI anomaly scoring.

---

## Quick Start Guide

1. Open the **SecureMailScope Analyst Workbench** in your browser at `http://localhost:5173`.
2. Click **"Upload PCAP"** on the Dashboard or Sidebar.
3. Select any `.pcap` file from this `demo_pcaps/` folder and upload it.
4. Click **"Analyze Capture"** to execute the pipeline.
5. Inspect the resulting findings, cryptographic profile, evidence timeline, and behavioral analysis!

---

## Demo Scenarios Overview

### 01_secure_smtp.pcap
- **What it demonstrates**: Genuinely secure mail transmission using modern cryptography (**TLS 1.3**, **AES-256-GCM**, Forward Secrecy) with a valid X.509 certificate containing Subject Alternative Names (SAN).
- **Expected Result**: **No HIGH/CRITICAL Security Findings**. May show `CERT-007` (Incomplete Chain — only the end-entity certificate is embedded in the PCAP; no intermediate CA is included). This is a forensically accurate observation, not a false alarm.
- **Where to Inspect**: Dashboard (Low Risk), Sessions Page (TLS 1.3), Certificate Page (Valid SAN Certificate).

### 02_deprecated_tls.pcap
- **What it demonstrates**: Detection of legacy, deprecated encryption (**TLS 1.0**) negotiated over STARTTLS.
- **Expected Result**: **High/Critical Risk Score (>70.0)**, Rule Violation `CRYPT-001` (Deprecated TLS Version).
- **Where to Inspect**: Findings Page (`CRYPT-001`), Sessions Page (negotiated TLS 1.0).

### 03_weak_cipher.pcap
- **What it demonstrates**: Detection of prohibited stream cipher suite (**RC4-SHA**).
- **Expected Result**: **Critical Risk Score (100.0)**, Rule Violation `CRYPT-005` (Prohibited Weak Cipher).
- **Where to Inspect**: Findings Page (`CRYPT-005`), Sessions Page (Cipher: `TLS_RSA_WITH_RC4_128_SHA`).

### 04_expired_certificate.pcap
- **What it demonstrates**: Historical certificate validity verification evaluated strictly against the PCAP capture timestamp.
- **Expected Result**: Rule Violation `CERT-001` (Certificate Expired at Capture Time).
- **Where to Inspect**: Findings Page (`CERT-001`), Certificates Page (Validity status flagged invalid).

### 05_starttls_rejected.pcap
- **What it demonstrates**: Explicit STARTTLS negotiation failure (Server returns `454 TLS not available` response).
- **Expected Result**: **Critical Risk Score (100.0)**, Rule Violation `STLS-002` (STARTTLS Rejected by Server).
- **Where to Inspect**: Sessions Page (STARTTLS State: `REJECTED`), Evidence Page (Frame #2 SMTP 454 response).

### 06_truncated_tls.pcap
- **What it demonstrates**: Forensic evidence uncertainty when ClientHello is sent but ServerHello is missing (truncated capture).
- **Expected Result**: **0 False Findings**, explicit `INSUFFICIENT_EVIDENCE` status.
- **Where to Inspect**: Sessions Page (Truncated state), Evidence Page.

### 07_multi_session_smtp.pcap
- **What it demonstrates**: Multi-flow PCAP processing containing 3 distinct mail sessions (mixed TLS 1.3, TLS 1.0, and Rejected STARTTLS) in a single file.
- **Expected Result**: **3 Discovered Mail Sessions**, Aggregated Job Risk Score **100.0**.
- **Where to Inspect**: Sessions Page (List of 3 sessions), Findings Page (Multiple session findings).

### 08_baseline_secure.pcap & 09_baseline_downgrade.pcap (Drift Pair)
- **What it demonstrates**: Baseline establishment and security posture drift detection across multiple captures over time.
- **How to test**:
  1. Upload and analyze `08_baseline_secure.pcap` first (Establishes secure baseline for server `198.51.100.30`).
  2. Upload and analyze `09_baseline_downgrade.pcap` second (Server `198.51.100.30` downgraded to TLS 1.0).
- **Expected Result**: `09_baseline_downgrade.pcap` detects **`TLS_VERSION_DOWNGRADED` Drift Event** and **Behavioral Anomaly** (`negotiated_tls_version` HIGH).
- **Where to Inspect**: Infrastructure Page (Drift Timeline), Behavioral Analysis Page (Anomalies card).

### 10_certificate_rotation.pcap
- **What it demonstrates**: Host identity stability across certificate rotation (same host IP `198.51.100.40`, updated 3072-bit RSA Certificate B).
- **Expected Result**: Maintains single infrastructure identity while registering `CERTIFICATE_CHANGED` drift event without false security alarms.
- **Where to Inspect**: Infrastructure Page (Certificate rotation event log).

---

## Machine-Readable Manifest

For automated test runners and API integrations, consult `demo_pcaps/manifest.json`.
