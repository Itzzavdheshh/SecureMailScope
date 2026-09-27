# SecureMailScope

> **AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**  
> *SIH 2026 — Problem Statement 26159 — NTRO*

---

## 🔒 Overview

SecureMailScope is an enterprise forensic network security assessment platform designed to inspect mail protocol network traffic captures (PCAPs), evaluate cryptographic postures (TLS, STARTTLS, X.509 Certificates), and identify cryptographic drift, weak ciphers, expired/self-signed certificates, and protocol vulnerabilities across SMTP, IMAP, and POP3 communications.

---

## 🚀 Key Features

- **PCAP Cryptographic Analysis**: Parse and dissect TLS handshakes, ciphersuites, key exchanges, and X.509 certificates from raw network captures.
- **STARTTLS State Machine Inspection**: Detect stripped STARTTLS, downgrade attacks, cleartext fallbacks, and anomalous post-STARTTLS handshakes.
- **X.509 Certificate Validation**: Evaluate validity periods dynamically against capture timestamp, key lengths, signature algorithms, self-signed certificates, SANs, and chain completeness.
- **Explainable Risk Scoring**: Deterministic, transparent risk weights formula with severity bands and clear rationale.
- **Forensic Workstation UI**: Modern dark-mode interface with live session timelines, interactive certificate visualizer, packet hex viewer, and executive report generator.

---

## 🛠 Tech Stack

- **Backend**: Python 3.12, FastAPI, dpkt, Scapy, Cryptography, SQLAlchemy, Pydantic v2
- **Frontend**: React 18, Vite, TypeScript, Lucide Icons, Recharts, Custom Forensic Workstation CSS
- **Containerization**: Docker, Docker Compose, Nginx

---

## 📂 Project Structure

```
SecureMailScope/
├── backend/            # FastAPI REST API & PCAP cryptographic engine
├── frontend/           # React + Vite + TypeScript forensic dashboard
├── rules/              # Versioned YAML security rules & risk weights
├── scripts/            # Synthetic test-PCAP traffic generator
├── docs/               # Architecture & specification documentation
└── docker-compose.yml  # Container orchestration setup
```

---

## 🚦 Quick Start

### 1. Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate      # On Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## 📜 License

Internal / Restricted — SIH 2026 NTRO Problem Statement 26159.
