# SecureMailScope

SecureMailScope analyzes packet captures of secure-email traffic and presents observed TLS, certificate, STARTTLS, infrastructure, drift, timeline, finding, and evidence data. It is an SIH 2026 demonstration for Problem Statement 26159 (NTRO), not a substitute for a full packet-analysis or PKI validation platform.

## Live Demo

- Frontend: https://securemailscope-frontend.vercel.app/
- API: https://securemailscope-g9b4.onrender.com/
- Health: https://securemailscope-g9b4.onrender.com/api/health

## Architecture

- React, TypeScript, and Vite frontend (`frontend/`), deployed on Vercel.
- FastAPI backend (`backend/`), deployed on Render.
- SQLAlchemy async persistence using SQLite locally and PostgreSQL on Render.
- Rule definitions and risk weights are YAML under `rules/`.
- PCAP/PCAPNG parsing uses dpkt with Scapy-based TLS dissection and Python cryptography for visible X.509 certificates.
- The backend stores packet-derived sessions, findings, evidence, profiles, timeline events, and reports in the database.

## Local Development

Backend (Python 3.12+):

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload
```

The example configuration uses local SQLite and `RULES_DIR=../rules`. Start the frontend in a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Vite proxies `/api` to `http://localhost:8000`. For a production frontend, set `VITE_API_BASE_URL` to the API root ending in `/api/v1`.

## Capture Workflow

Upload a `.pcap` or `.pcapng` file from Intake. The API validates the capture format, packet records and upload size, calculates SHA-256, detects duplicate content, stores the file, and creates an analysis job. Analysis currently runs synchronously when the job start endpoint is called. The workspace then shows the persisted job results for the selected capture.

Each finding links to evidence records containing the capture, session, frame number, timestamp, protocol layer, observed field/value, and evidence status. Reports are generated from stored analysis data. They do not create packet evidence that was not observed.

## Risk Scoring

Session raw risk is the sum of configured severity weights multiplied by finding-confidence factors. The normalized score is `min(100, raw_score / 30 * 100)`, rounded to one decimal place. Job risk is `0.7 * max(session scores) + 0.3 * average(session scores)`, capped at 100. No findings produce score 0 / `SECURE`. `INSUFFICIENT_EVIDENCE` contributes zero.

Session bands are `SECURE` (0–19.9), `LOW` (20–39.9), `MEDIUM` (40–59.9), `HIGH` (60–79.9), and `CRITICAL` (80–100). The YAML configuration in `rules/risk_weights.yaml` is the source for severity weights, confidence factors, normalization reference, and documented bands.

## Demo PCAP Lab

`demo_pcaps/` contains generated binary test captures built for repeatable protocol scenarios. They are controlled lab fixtures, not captures from real organizations or incidents. Scenario descriptions and observed outputs are kept in `demo_pcaps/README.md` and `demo_pcaps/manifest.json`; verify results against the current scenario tests rather than treating a manifest entry as proof by itself.

Included scenarios cover secure SMTP, deprecated TLS, weak ciphers, expired certificates, rejected STARTTLS, truncated handshakes, multiple sessions, baseline downgrade, and certificate rotation.

## Behavioral Analysis

Behavioral output combines deterministic profile comparisons with statistical checks when enough baseline observations exist. The Isolation Forest is only run when its minimum history requirements are met. Reports identify insufficient data and limitations; behavioral results do not replace deterministic packet-backed findings.

## Deployment

- Render runs the FastAPI service from `backend/` and provisions PostgreSQL using `render.yaml`.
- Vercel hosts `frontend/`; configure `VITE_API_BASE_URL=https://securemailscope-g9b4.onrender.com/api/v1` in the Vercel project and redeploy after changing it.
- Configure Render `CORS_ORIGINS` with the exact deployed frontend origin.
- Do not commit `.env` files or service credentials.

## Limitations

- Render's configured `/tmp/uploads` is ephemeral. Database-backed analysis results remain useful after a file disappears, but reanalysis and source-PCAP access require the original upload to still exist. Persistent object storage is a production enhancement.
- Baseline profiles are process-local in-memory state and reset on service restart; they are not a durable cross-instance history.
- Analysis runs in the API request path; there is no durable distributed worker queue.
- The public SIH demo does not implement user authentication, rate limiting, or an append-only chain-of-custody service. Do not use it as a production multi-tenant forensic service.
- TLS 1.3 encrypts handshake messages after ServerHello in ordinary full handshakes. Certificate details are reported only when certificate bytes are observable in the capture, such as TLS 1.2 handshakes or captures with suitable decryption context; missing certificate visibility is not proof of a valid certificate.
- The demo PCAPs are intentionally generated scenarios and do not model all network stacks, TLS extensions, fragmentation, or capture loss patterns.

## Tests

Run from the repository root:

```powershell
.\backend\venv\Scripts\pytest.exe -q
.\backend\venv\Scripts\pytest.exe .\backend\tests\test_phase9_scenarios.py -q
cd frontend
npx tsc --noEmit
npm run build
```
