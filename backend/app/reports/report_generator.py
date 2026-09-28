"""
Deterministic Report Generation Engine.
Assembles analyzed investigation data from database and renders structured JSON, standalone dark HTML,
and ReportLab PDF investigation reports using factual evidence language.
"""

import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Capture,
    AnalysisJob,
    EmailSession,
    TlsHandshake,
    Certificate,
    CertificateChain,
    StarttlsState,
    Finding,
    Evidence,
    InfrastructureIdentity,
    DriftEvent,
    TimelineEvent,
    RiskBand,
    BehavioralAnalysis,
)

# ReportLab imports for PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


async def build_report_data_graph(db: AsyncSession, job_id: str) -> Optional[Dict[str, Any]]:
    """Query complete graph of domain objects for an AnalysisJob."""
    job_stmt = select(AnalysisJob).where(AnalysisJob.id == job_id)
    job_res = await db.execute(job_stmt)
    job = job_res.scalar_one_or_none()
    if not job:
        return None

    cap_stmt = select(Capture).where(Capture.id == job.capture_id)
    cap_res = await db.execute(cap_stmt)
    capture = cap_res.scalar_one_or_none()

    sess_stmt = (
        select(EmailSession)
        .options(
            selectinload(EmailSession.tls_handshake),
            selectinload(EmailSession.certificates),
            selectinload(EmailSession.certificate_chain),
            selectinload(EmailSession.starttls_details),
            selectinload(EmailSession.findings).selectinload(Finding.evidence),
        )
        .where(EmailSession.job_id == job.id)
        .order_by(EmailSession.session_index.asc())
    )
    sess_res = await db.execute(sess_stmt)
    sessions = list(sess_res.scalars().all())

    find_stmt = (
        select(Finding)
        .options(selectinload(Finding.evidence))
        .where(Finding.job_id == job.id)
        .order_by(Finding.severity.desc())
    )
    find_res = await db.execute(find_stmt)
    findings = list(find_res.scalars().all())

    drift_stmt = select(DriftEvent).where(DriftEvent.job_id == job.id)
    drift_res = await db.execute(drift_stmt)
    drifts = list(drift_res.scalars().all())

    tm_stmt = (
        select(TimelineEvent)
        .where(TimelineEvent.job_id == job.id)
        .order_by(TimelineEvent.timestamp.asc(), TimelineEvent.frame_number.asc())
    )
    tm_res = await db.execute(tm_stmt)
    timeline = list(tm_res.scalars().all())

    infra_stmt = (
        select(InfrastructureIdentity)
        .options(selectinload(InfrastructureIdentity.drift_events))
        .where(InfrastructureIdentity.last_evaluated_job_id == job.id)
    )
    infra_res = await db.execute(infra_stmt)
    infrastructure = list(infra_res.scalars().all())

    # Phase 10: Behavioral analyses for this job
    behav_stmt = (
        select(BehavioralAnalysis)
        .where(BehavioralAnalysis.job_id == job.id)
        .order_by(BehavioralAnalysis.analyzed_at.asc())
    )
    behav_res = await db.execute(behav_stmt)
    behavioral_analyses = list(behav_res.scalars().all())

    sev_dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_dist[s_val] = sev_dist.get(s_val, 0) + 1

    limitations: List[str] = [
        "Offline PCAP evidence analysis cannot independently verify real-world OCSP/CRL revocation status unless present in packet stream.",
        "Observed session security posture is evaluated strictly at capture time.",
    ]

    missing_tls = [s for s in sessions if not s.tls_handshake and not s.is_tls_implicit]
    if missing_tls:
        limitations.append(
            f"TLS handshake was not observed for {len(missing_tls)} plaintext or unupgraded session(s)."
        )

    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "report_metadata": {
            "report_id": f"REP-{job.id[:8]}",
            "generated_at": now_iso,
            "tool_version": "SecureMailScope v1.0.0 (Phase 7)",
        },
        "capture": {
            "id": capture.id if capture else job.capture_id,
            "filename": capture.filename if capture else "Unknown",
            "file_size_bytes": capture.file_size_bytes if capture else 0,
            "sha256_hash": capture.sha256_hash if capture else "N/A",
            "total_packets": capture.total_packets if capture else 0,
            "created_at": capture.created_at.isoformat() if capture and capture.created_at else "N/A",
        },
        "executive_summary": {
            "job_id": job.id,
            "overall_risk_score": job.overall_risk_score or 0.0,
            "risk_band": job.risk_band.value if hasattr(job.risk_band, "value") else str(job.risk_band or "SECURE"),
            "total_sessions": len(sessions),
            "total_findings": len(findings),
            "severity_distribution": sev_dist,
            "drift_count": len(drifts),
            "completed_at": job.completed_at.isoformat() if job.completed_at else "N/A",
        },
        "sessions": [
            {
                "id": s.id,
                "session_index": s.session_index,
                "client": f"{s.client_ip}:{s.client_port}",
                "server": f"{s.server_ip}:{s.server_port}",
                "protocol": s.protocol.value if hasattr(s.protocol, "value") else str(s.protocol),
                "starttls_state": s.starttls_state.value if hasattr(s.starttls_state, "value") else str(s.starttls_state),
                "is_tls_implicit": s.is_tls_implicit,
                "risk_score": s.risk_score or 0.0,
                "packet_count": s.packet_count,
                "bytes_transferred": s.bytes_transferred,
                "banner": s.banner,
                "hostname": s.hostname,
                "tls": {
                    "version": s.tls_handshake.negotiated_tls_version if s.tls_handshake else None,
                    "cipher": s.tls_handshake.negotiated_cipher_suite if s.tls_handshake else None,
                    "forward_secrecy": s.tls_handshake.is_forward_secrecy if s.tls_handshake else None,
                    "key_exchange": s.tls_handshake.key_exchange_group if s.tls_handshake else None,
                } if s.tls_handshake else None,
                "certificates": [
                    {
                        "subject": c.subject_dn,
                        "issuer": c.issuer_dn,
                        "fingerprint": c.sha256_fingerprint,
                        "valid_at_capture": c.is_valid_at_capture,
                        "signature_alg": c.signature_algorithm,
                        "public_key": f"{c.public_key_type} {c.public_key_size_bits}b",
                    }
                    for c in s.certificates
                ] if s.certificates else [],
            }
            for s in sessions
        ],
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "score_contribution": f.score_contribution,
                "description": f.description,
                "remediation": f.remediation_recommendation,
                "evidence_count": len(f.evidence),
                "evidence": [
                    {
                        "frame_number": ev.frame_number,
                        "packet_timestamp": ev.packet_timestamp,
                        "protocol_layer": ev.protocol_layer,
                        "field_name": ev.field_name,
                        "observed_value": ev.observed_value,
                    }
                    for ev in f.evidence
                ],
            }
            for f in findings
        ],
        "infrastructure": [
            {
                "id": inf.id,
                "ip_address": inf.ip_address,
                "hostname": inf.hostname,
                "first_seen_at": inf.first_seen_at.isoformat(),
                "last_seen_at": inf.last_seen_at.isoformat(),
                "current_risk_score": inf.current_risk_score,
                "drift_event_count": len(inf.drift_events),
            }
            for inf in infrastructure
        ],
        "drifts": [
            {
                "id": d.id,
                "infrastructure_id": d.infrastructure_id,
                "event_type": d.event_type.value if hasattr(d.event_type, "value") else str(d.event_type),
                "delta_description": d.delta_description,
                "risk_delta": d.risk_delta,
                "detected_at": d.detected_at.isoformat(),
                "previous_state": d.previous_state,
                "new_state": d.new_state,
            }
            for d in drifts
        ],
        "timeline": [
            {
                "timestamp": t.timestamp,
                "frame_number": t.frame_number,
                "event_type": t.event_type,
                "summary": t.summary,
                "severity": t.severity.value if hasattr(t.severity, "value") else str(t.severity),
            }
            for t in timeline
        ],
        "behavioral_analysis": {
            "total_analyses": len(behavioral_analyses),
            "significant_deviations": sum(1 for b in behavioral_analyses if b.significant_deviation_detected),
            "insufficient_data": sum(
                1 for b in behavioral_analyses
                if (b.overall_status.value if hasattr(b.overall_status, "value") else str(b.overall_status))
                == "INSUFFICIENT_EVIDENCE"
            ),
            "total_anomalies": sum(b.anomaly_count for b in behavioral_analyses),
            "results": [
                {
                    "id": b.id,
                    "session_id": b.session_id,
                    "identity_key": b.identity_key,
                    "baseline_status": b.baseline_status,
                    "observation_count": b.observation_count,
                    "overall_status": b.overall_status.value if hasattr(b.overall_status, "value") else str(b.overall_status),
                    "significant_deviation_detected": b.significant_deviation_detected,
                    "deviation_summary": b.deviation_summary,
                    "anomaly_count": b.anomaly_count,
                    "analyzed_at": b.analyzed_at.isoformat() if b.analyzed_at else None,
                }
                for b in behavioral_analyses
            ],
        },
        "limitations": limitations,
    }


def generate_json_report(data: Dict[str, Any]) -> str:
    """Format report data dict as clean formatted JSON."""
    return json.dumps(data, indent=2)


def generate_html_report(data: Dict[str, Any]) -> str:
    """Render standalone, offline-capable dark HTML investigation report."""
    meta = data.get("report_metadata", {})
    cap = data.get("capture", {})
    exec_sum = data.get("executive_summary", {})
    findings = data.get("findings", [])
    sessions = data.get("sessions", [])
    drifts = data.get("drifts", [])
    timeline = data.get("timeline", [])
    limitations = data.get("limitations", [])

    risk_score = exec_sum.get("overall_risk_score", 0.0)
    risk_band = exec_sum.get("risk_band", "SECURE")

    badge_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
        "SECURE": "#10b981",
    }.get(risk_band, "#6b7280")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Forensic Investigation Report — {meta.get('report_id', '')}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --panel: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
            color: var(--accent);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 14px;
            color: #ffffff;
            background: {badge_color};
        }}
        .card {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card h2 {{
            margin-top: 0;
            font-size: 18px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            color: var(--accent);
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}
        .stat {{
            font-size: 24px;
            font-weight: bold;
            color: #ffffff;
        }}
        .stat-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 14px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f172a;
            color: var(--text-muted);
        }}
        .sev-CRITICAL {{ color: #ef4444; font-weight: bold; }}
        .sev-HIGH {{ color: #f97316; font-weight: bold; }}
        .sev-MEDIUM {{ color: #eab308; }}
        .sev-LOW {{ color: #3b82f6; }}
        .sev-INFO {{ color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>SecureMailScope Investigation Report</h1>
                <div style="color: var(--text-muted); font-size: 14px;">
                    Report ID: {meta.get('report_id', '')} | Generated: {meta.get('generated_at', '')}
                </div>
            </div>
            <div>
                <span class="badge">{risk_band} ({risk_score:.1f} / 100.0)</span>
            </div>
        </div>

        <div class="card">
            <h2>Executive Summary & Posture</h2>
            <div class="grid">
                <div>
                    <div class="stat">{exec_sum.get('overall_risk_score', 0.0):.1f}</div>
                    <div class="stat-label">Overall Risk Score</div>
                </div>
                <div>
                    <div class="stat">{exec_sum.get('total_sessions', 0)}</div>
                    <div class="stat-label">Mail Sessions</div>
                </div>
                <div>
                    <div class="stat">{exec_sum.get('total_findings', 0)}</div>
                    <div class="stat-label">Security Findings</div>
                </div>
                <div>
                    <div class="stat">{exec_sum.get('drift_count', 0)}</div>
                    <div class="stat-label">Drift Events</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Capture Metadata</h2>
            <p><strong>Filename:</strong> {cap.get('filename', 'N/A')}</p>
            <p><strong>SHA-256 Hash:</strong> <code>{cap.get('sha256_hash', 'N/A')}</code></p>
            <p><strong>File Size:</strong> {cap.get('file_size_bytes', 0):,} bytes | <strong>Packets:</strong> {cap.get('total_packets', 0):,}</p>
        </div>

        <div class="card">
            <h2>Security Findings ({len(findings)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
    for f in findings:
        sev = f.get("severity", "INFO")
        html += f"""
                    <tr>
                        <td><code>{f.get('rule_id')}</code></td>
                        <td class="sev-{sev}">{sev}</td>
                        <td><strong>{f.get('title')}</strong></td>
                        <td>{f.get('description')}</td>
                    </tr>
"""

    html += """
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Observed Mail Sessions</h2>
            <table>
                <thead>
                    <tr>
                        <th>Index</th>
                        <th>Client -> Server</th>
                        <th>Protocol</th>
                        <th>STARTTLS</th>
                        <th>Negotiated TLS</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
"""
    for s in sessions:
        tls_info = s.get("tls")
        tls_ver = tls_info.get("version", "None") if tls_info else ("Implicit TLS" if s.get("is_tls_implicit") else "Plaintext")
        html += f"""
                    <tr>
                        <td>#{s.get('session_index')}</td>
                        <td>{s.get('client')} &rarr; {s.get('server')}</td>
                        <td>{s.get('protocol')}</td>
                        <td>{s.get('starttls_state')}</td>
                        <td>{tls_ver}</td>
                        <td>{s.get('risk_score', 0.0):.1f}</td>
                    </tr>
"""

    html += """
                </tbody>
            </table>
        </div>
"""

    if drifts:
        html += """
        <div class="card">
            <h2>Observed Cryptographic Drift Events</h2>
            <table>
                <thead>
                    <tr>
                        <th>Event Type</th>
                        <th>Delta Description</th>
                        <th>Risk Delta</th>
                        <th>Detected At</th>
                    </tr>
                </thead>
                <tbody>
"""
        for d in drifts:
            html += f"""
                    <tr>
                        <td><strong>{d.get('event_type')}</strong></td>
                        <td>{d.get('delta_description')}</td>
                        <td>+{d.get('risk_delta', 0.0):.1f}</td>
                        <td>{d.get('detected_at')}</td>
                    </tr>
"""
        html += """
                </tbody>
            </table>
        </div>
"""

    if timeline:
        html += """
        <div class="card">
            <h2>Forensic Investigation Timeline</h2>
            <table>
                <thead>
                    <tr>
                        <th>Frame</th>
                        <th>Event Type</th>
                        <th>Forensic Summary</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
"""
        for t in timeline[:30]:  # Limit top 30 in HTML
            sev = t.get("severity", "INFO")
            html += f"""
                    <tr>
                        <td>{t.get('frame_number') or '-'}</td>
                        <td><code>{t.get('event_type')}</code></td>
                        <td>{t.get('summary')}</td>
                        <td class="sev-{sev}">{sev}</td>
                    </tr>
"""
        html += """
                </tbody>
            </table>
        </div>
"""

    html += """
        <div class="card">
            <h2>Evidence Limitations & Insufficient Data</h2>
            <ul>
"""
    for lim in limitations:
        html += f"<li>{lim}</li>"

    html += """
            </ul>
        </div>
    </div>
</body>
</html>
"""
    return html


def generate_pdf_report(data: Dict[str, Any]) -> bytes:
    """Generate printable investigation PDF report using ReportLab."""
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    h2_style = ParagraphStyle(
        "ReportH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0284c7"),
        spaceBefore=12,
        spaceAfter=6,
    )
    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )

    elements = []

    meta = data.get("report_metadata", {})
    cap = data.get("capture", {})
    exec_sum = data.get("executive_summary", {})
    findings = data.get("findings", [])
    sessions = data.get("sessions", [])
    drifts = data.get("drifts", [])
    timeline = data.get("timeline", [])
    limitations = data.get("limitations", [])

    # Header
    elements.append(Paragraph("SecureMailScope Forensic Investigation Report", title_style))
    elements.append(Paragraph(f"Report ID: {meta.get('report_id')} | Generated: {meta.get('generated_at')}", normal_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # Executive Summary Table
    risk_score = exec_sum.get("overall_risk_score", 0.0)
    risk_band = exec_sum.get("risk_band", "SECURE")

    summary_data = [
        [
            Paragraph("<b>Overall Risk Score</b>", normal_style),
            Paragraph(f"<b>{risk_score:.1f} / 100.0</b> ({risk_band})", normal_style),
        ],
        [
            Paragraph("<b>Capture Filename</b>", normal_style),
            Paragraph(str(cap.get("filename")), normal_style),
        ],
        [
            Paragraph("<b>SHA-256 Hash</b>", normal_style),
            Paragraph(str(cap.get("sha256_hash")), code_style),
        ],
        [
            Paragraph("<b>Total Sessions / Findings</b>", normal_style),
            Paragraph(f"{exec_sum.get('total_sessions')} Sessions | {exec_sum.get('total_findings')} Findings | {exec_sum.get('drift_count')} Drifts", normal_style),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[2.0 * inch, 5.0 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Findings Table
    if findings:
        elements.append(Paragraph(f"Security Findings ({len(findings)})", h2_style))
        find_table_data = [
            [
                Paragraph("<b>Rule ID</b>", normal_style),
                Paragraph("<b>Sev</b>", normal_style),
                Paragraph("<b>Title & Description</b>", normal_style),
            ]
        ]
        for f in findings:
            find_table_data.append(
                [
                    Paragraph(str(f.get("rule_id")), code_style),
                    Paragraph(str(f.get("severity")), normal_style),
                    Paragraph(f"<b>{f.get('title')}</b><br/>{f.get('description')}", normal_style),
                ]
            )

        find_table = Table(find_table_data, colWidths=[1.2 * inch, 0.8 * inch, 5.0 * inch])
        find_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(find_table)
        elements.append(Spacer(1, 12))

    # Sessions Summary
    if sessions:
        elements.append(Paragraph(f"Observed Mail Sessions ({len(sessions)})", h2_style))
        sess_table_data = [
            [
                Paragraph("<b>#</b>", normal_style),
                Paragraph("<b>Client -> Server</b>", normal_style),
                Paragraph("<b>Proto</b>", normal_style),
                Paragraph("<b>STARTTLS</b>", normal_style),
                Paragraph("<b>TLS Version</b>", normal_style),
            ]
        ]
        for s in sessions:
            tls_info = s.get("tls")
            tls_v = tls_info.get("version") if tls_info else ("Implicit TLS" if s.get("is_tls_implicit") else "Plaintext")
            sess_table_data.append(
                [
                    Paragraph(f"#{s.get('session_index')}", normal_style),
                    Paragraph(f"{s.get('client')} &rarr;<br/>{s.get('server')}", normal_style),
                    Paragraph(str(s.get("protocol")), normal_style),
                    Paragraph(str(s.get("starttls_state")), normal_style),
                    Paragraph(str(tls_v or "None"), normal_style),
                ]
            )
        sess_table = Table(sess_table_data, colWidths=[0.5 * inch, 2.3 * inch, 1.0 * inch, 1.6 * inch, 1.6 * inch])
        sess_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(sess_table)
        elements.append(Spacer(1, 12))

    # Limitations
    if limitations:
        elements.append(Paragraph("Evidence Limitations", h2_style))
        for lim in limitations:
            elements.append(Paragraph(f"• {lim}", normal_style))

    doc.build(elements)
    return pdf_buffer.getvalue()
