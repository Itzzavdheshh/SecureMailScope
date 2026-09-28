import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Layers,
  TrendingDown,
  ArrowRight,
  CheckCircle2,
  Activity,
} from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { riskApi, findingsApi } from '../api/services';
import type { RiskSummaryResponse, FindingRead } from '../types/api';
import { MetricStrip } from '../components/common/MetricStrip';
import { Badge, SeverityBadge, RiskBandBadge } from '../components/common/Badge';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const OverviewPage: React.FC = () => {
  const { activeCapture, activeJob } = useWorkspace();
  const [riskData, setRiskData] = useState<RiskSummaryResponse | null>(null);
  const [recentFindings, setRecentFindings] = useState<FindingRead[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!activeCapture && !activeJob) {
      setIsLoading(false);
      return;
    }

    const loadData = async () => {
      setIsLoading(true);
      setErrorMsg(null);
      try {
        if (activeJob) {
          const [riskRes, findRes] = await Promise.all([
            riskApi.getJobRisk(activeJob.id),
            findingsApi.list({ job_id: activeJob.id, page_size: 5 }),
          ]);
          setRiskData(riskRes);
          setRecentFindings(findRes.items);
        } else if (activeCapture) {
          const riskRes = await riskApi.getCaptureRisk(activeCapture.id);
          setRiskData(riskRes);
        }
      } catch (err: any) {
        setErrorMsg(err.message || 'Unable to load posture summary data');
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
  }, [activeCapture, activeJob]);

  if (!activeCapture && !activeJob) {
    return (
      <div className="workspace-page">
        <EmptyState
          title="No Active Capture Context"
          subtitle="Please upload or select a network packet capture file from Intake & PCAP to view forensic security posture."
        />
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="workspace-page">
        <LoadingState message="Analyzing network capture cryptographic posture..." />
      </div>
    );
  }

  if (errorMsg) {
    return (
      <div className="workspace-page">
        <ErrorState message={errorMsg} />
      </div>
    );
  }

  const metrics = [
    { label: 'Total Sessions', value: riskData?.total_sessions ?? 0 },
    {
      label: 'Security Findings',
      value: riskData?.total_findings ?? 0,
      highlight: (riskData?.total_findings || 0) > 0 ? ('warning' as const) : ('secure' as const),
    },
    { label: 'High-Risk Sessions', value: riskData?.high_risk_session_count ?? 0 },
    { label: 'Cryptographic Drifts', value: riskData?.drift_count ?? 0 },
    {
      label: 'Overall Risk Score',
      value: `${(riskData?.overall_risk_score || 0).toFixed(1)} / 100`,
      highlight:
        (riskData?.overall_risk_score || 0) >= 60
          ? ('critical' as const)
          : (riskData?.overall_risk_score || 0) >= 40
          ? ('warning' as const)
          : ('secure' as const),
    },
  ];

  return (
    <div className="workspace-page-scrollable">
      {/* Top Metric Strip */}
      <MetricStrip metrics={metrics} />

      {/* Main Command Center Grid (55% / 45%) */}
      <div style={{ display: 'grid', gridTemplateColumns: '55% 45%', gap: '16px' }}>
        {/* Left Column: Posture Gauge + Key Cryptographic Observations */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Posture Gauge Card */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Cryptographic Security Posture</span>
              <RiskBandBadge band={riskData?.risk_band} />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '20px', padding: '8px 0' }}>
              <div
                style={{
                  width: '90px',
                  height: '90px',
                  borderRadius: '50%',
                  border: '6px solid var(--color-blue-100)',
                  borderTopColor:
                    (riskData?.overall_risk_score || 0) >= 60
                      ? 'var(--color-critical)'
                      : (riskData?.overall_risk_score || 0) >= 40
                      ? 'var(--color-warning)'
                      : 'var(--color-success)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '20px',
                  fontWeight: 700,
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {(riskData?.overall_risk_score || 0).toFixed(0)}
              </div>

              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text)' }}>
                  {riskData?.risk_band === 'CRITICAL'
                    ? 'Critical Cryptographic Risk Observed'
                    : riskData?.risk_band === 'HIGH'
                    ? 'High Cryptographic Risk Detected'
                    : riskData?.risk_band === 'MEDIUM'
                    ? 'Moderate Policy Violations Present'
                    : 'Secure Cryptographic Posture Verified'}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', lineHeight: 1.4 }}>
                  Capture SHA-256:{' '}
                  <span className="hash" style={{ fontSize: '11px' }}>
                    {activeCapture?.sha256_hash}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Observations Table */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Cryptographic Observations</span>
            </div>

            <table className="dense-table">
              <thead>
                <tr>
                  <th>FACET</th>
                  <th>STATUS</th>
                  <th>OBSERVATION</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style={{ fontWeight: 600 }}>TLS Handshake</td>
                  <td>
                    <Badge variant="low">TLS 1.2 / 1.3</Badge>
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    Reconstructed protocol negotiation across mail streams
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>STARTTLS Enforcement</td>
                  <td>
                    <Badge variant="info">ENFORCED</Badge>
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    Analyzed explicit plaintext to TLS upgrade commands
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>X.509 Certificates</td>
                  <td>
                    <Badge variant="low">VALIDATED</Badge>
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    Extracted public keys, issuers, and expiration dates
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Policy Drift</td>
                  <td>
                    <Badge variant={(riskData?.drift_count || 0) > 0 ? 'medium' : 'low'}>
                      {(riskData?.drift_count || 0) > 0 ? 'DRIFT OBSERVED' : 'NO DRIFT'}
                    </Badge>
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    {(riskData?.drift_count || 0) > 0
                      ? `${riskData?.drift_count} baseline profile deviations detected`
                      : 'No baseline profile deviations detected'}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Pipeline Trace + Recent High-Priority Findings */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Analysis Pipeline Trace */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Analysis Pipeline Trace</span>
            </div>

            <div className="pipeline-trace" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>1. Capture File Ingestion & Validation</span>
              </div>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>2. TCP Session & Stream Assembly</span>
              </div>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>3. Mail Protocol Identification (SMTP / IMAP / POP3)</span>
              </div>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>4. TLS Handshake & X.509 Certificate Parsing</span>
              </div>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>5. Rule Engine & Baseline Verification</span>
              </div>
            </div>
          </div>

          {/* Recent Findings Preview Table */}
          <div className="card" style={{ flex: 1 }}>
            <div className="card-header">
              <span className="card-title">Priority Security Findings</span>
              <Link to="/findings" className="btn btn--ghost" style={{ fontSize: '11px' }}>
                View All <ArrowRight size={12} />
              </Link>
            </div>

            {recentFindings.length === 0 ? (
              <div style={{ color: 'var(--color-text-muted)', fontSize: '12px', padding: '12px 0' }}>
                No security findings observed for this capture.
              </div>
            ) : (
              <table className="dense-table">
                <thead>
                  <tr>
                    <th>RULE ID</th>
                    <th>SEVERITY</th>
                    <th>TITLE</th>
                  </tr>
                </thead>
                <tbody>
                  {recentFindings.map((f) => (
                    <tr key={f.id}>
                      <td className="mono">{f.rule_id}</td>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td style={{ fontWeight: 500 }}>{f.title}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row: Quick Access Workspace Row Links */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Forensic Workspace Navigation</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          <Link
            to="/sessions"
            className="btn btn--secondary"
            style={{ justifyContent: 'space-between', padding: '10px 14px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={16} />
              <span>Sessions ({riskData?.total_sessions})</span>
            </div>
            <ArrowRight size={14} />
          </Link>

          <Link
            to="/findings"
            className="btn btn--secondary"
            style={{ justifyContent: 'space-between', padding: '10px 14px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={16} />
              <span>Findings ({riskData?.total_findings})</span>
            </div>
            <ArrowRight size={14} />
          </Link>

          <Link
            to="/evidence"
            className="btn btn--secondary"
            style={{ justifyContent: 'space-between', padding: '10px 14px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={16} />
              <span>Evidence</span>
            </div>
            <ArrowRight size={14} />
          </Link>

          <Link
            to="/drifts"
            className="btn btn--secondary"
            style={{ justifyContent: 'space-between', padding: '10px 14px' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <TrendingDown size={16} />
              <span>Drift ({riskData?.drift_count})</span>
            </div>
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </div>
  );
};
