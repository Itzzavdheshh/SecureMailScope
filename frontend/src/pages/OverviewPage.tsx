import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Layers,
  TrendingDown,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Circle,
  Activity,
} from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { riskApi, findingsApi } from '../api/services';
import type { RiskSummaryResponse, FindingRead } from '../types/api';
import { MetricStrip } from '../components/common/MetricStrip';
import { Badge, SeverityBadge, RiskBandBadge } from '../components/common/Badge';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const OverviewPage: React.FC = () => {
  const { investigationName, capturesList, activeCapture, activeJob } = useWorkspace();
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

  const hasSessions = (riskData?.total_sessions || 0) > 0;

  const metrics = [
    { label: 'Total Sessions', value: riskData?.total_sessions ?? 0 },
    {
      label: 'Security Findings',
      value: riskData?.total_findings ?? 0,
      highlight: (riskData?.total_findings || 0) > 0 ? ('warning' as const) : hasSessions ? ('secure' as const) : ('info' as const),
    },
    { label: 'High-Risk Sessions', value: riskData?.high_risk_session_count ?? 0 },
    { label: 'Cryptographic Drifts', value: riskData?.drift_count ?? 0 },
    {
      label: 'Overall Risk Score',
      value: `${(riskData?.overall_risk_score || 0).toFixed(1)} / 100`,
      highlight: !hasSessions
        ? ('info' as const)
        : (riskData?.overall_risk_score || 0) >= 60
        ? ('critical' as const)
        : (riskData?.overall_risk_score || 0) >= 40
        ? ('warning' as const)
        : ('secure' as const),
    },
  ];

  return (
    <div className="workspace-page-scrollable">
      {/* Investigation Context Banner */}
      <div className="card" style={{ marginBottom: '16px', background: 'var(--color-bg-primary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px' }}>
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-blue-700)', letterSpacing: '0.05em' }}>
              INVESTIGATION WORKSPACE OVERVIEW
            </div>
            <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--color-text)', marginTop: '2px' }}>
              {investigationName}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
              Captures in Registry: <span className="mono" style={{ fontWeight: 600 }}>{capturesList.length}</span> • Currently Analyzing: <span className="mono" style={{ fontWeight: 700, color: 'var(--color-blue-700)' }}>{activeCapture?.filename || 'No Capture Selected'}</span>
            </div>
          </div>
          {activeCapture && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)' }}>POSTURE SCORE</div>
              <div className="mono" style={{ fontSize: '18px', fontWeight: 700, color: (activeJob?.overall_risk_score || 0) >= 40 ? 'var(--color-high)' : 'var(--color-success)' }}>
                {activeJob?.overall_risk_score !== null && activeJob?.overall_risk_score !== undefined ? `${activeJob.overall_risk_score.toFixed(1)} / 100` : 'UNEVALUATED'}
              </div>
            </div>
          )}
        </div>
      </div>

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
              {hasSessions ? (
                <RiskBandBadge band={riskData?.risk_band} />
              ) : (
                <Badge variant="neutral">INSUFFICIENT EVIDENCE</Badge>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '20px', padding: '8px 0' }}>
              <div
                style={{
                  width: '90px',
                  height: '90px',
                  borderRadius: '50%',
                  border: '6px solid var(--color-blue-100)',
                  borderTopColor: !hasSessions
                    ? 'var(--color-border-strong)'
                    : (riskData?.overall_risk_score || 0) >= 60
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
                  color: !hasSessions ? 'var(--color-text-muted)' : 'inherit',
                }}
              >
                {(riskData?.overall_risk_score || 0).toFixed(0)}
              </div>

              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text)' }}>
                  {!hasSessions
                    ? 'INSUFFICIENT EVIDENCE'
                    : riskData?.risk_band === 'CRITICAL'
                    ? 'Critical Cryptographic Risk Observed'
                    : riskData?.risk_band === 'HIGH'
                    ? 'High Cryptographic Risk Detected'
                    : riskData?.risk_band === 'MEDIUM'
                    ? 'Moderate Policy Violations Present'
                    : 'Secure Cryptographic Posture Verified'}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', lineHeight: 1.4 }}>
                  {!hasSessions
                    ? 'No security-relevant mail observations available in capture'
                    : `Capture SHA-256: ${activeCapture?.sha256_hash}`}
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
                    {hasSessions ? (
                      <Badge variant="low">OBSERVED</Badge>
                    ) : (
                      <Badge variant="neutral">NOT OBSERVED</Badge>
                    )}
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    {hasSessions
                      ? 'Reconstructed protocol negotiation across mail streams'
                      : 'No TLS handshakes observed in capture'}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>STARTTLS State</td>
                  <td>
                    {hasSessions ? (
                      <Badge variant="info">ANALYZED</Badge>
                    ) : (
                      <Badge variant="neutral">INSUFFICIENT EVIDENCE</Badge>
                    )}
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    {hasSessions
                      ? 'Analyzed explicit plaintext to TLS upgrade commands'
                      : 'No STARTTLS commands observed'}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>X.509 Certificates</td>
                  <td>
                    {hasSessions ? (
                      <Badge variant="low">ANALYZED</Badge>
                    ) : (
                      <Badge variant="neutral">NOT OBSERVED</Badge>
                    )}
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    {hasSessions
                      ? 'Extracted public keys, issuers, and expiration dates'
                      : 'No certificates presented'}
                  </td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Policy Drift</td>
                  <td>
                    {!hasSessions ? (
                      <Badge variant="neutral">NOT ASSESSED</Badge>
                    ) : (
                      <Badge variant={(riskData?.drift_count || 0) > 0 ? 'medium' : 'low'}>
                        {(riskData?.drift_count || 0) > 0 ? 'DRIFT OBSERVED' : 'NO DRIFT'}
                      </Badge>
                    )}
                  </td>
                  <td style={{ color: 'var(--color-text-secondary)' }}>
                    {!hasSessions
                      ? 'Insufficient baseline evidence'
                      : (riskData?.drift_count || 0) > 0
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
                <span>2. TCP Session & Stream Processing</span>
              </div>
              <div className={`pipeline-step ${hasSessions ? 'completed' : 'warning'}`}>
                {hasSessions ? (
                  <CheckCircle2 size={16} color="var(--color-success)" />
                ) : (
                  <AlertTriangle size={16} color="var(--color-warning)" />
                )}
                <span>
                  3. Mail Protocol Identification —{' '}
                  {hasSessions ? `${riskData?.total_sessions} sessions identified` : 'No mail session reconstructed'}
                </span>
              </div>
              <div className={`pipeline-step ${hasSessions ? 'completed' : 'not-observed'}`}>
                {hasSessions ? (
                  <CheckCircle2 size={16} color="var(--color-success)" />
                ) : (
                  <Circle size={16} color="var(--color-text-muted)" />
                )}
                <span>
                  4. TLS & X.509 Handshake Analysis — {hasSessions ? 'Extracted' : 'Not observed'}
                </span>
              </div>
              <div className={`pipeline-step ${hasSessions ? 'completed' : 'not-observed'}`}>
                {hasSessions ? (
                  <CheckCircle2 size={16} color="var(--color-success)" />
                ) : (
                  <Circle size={16} color="var(--color-text-muted)" />
                )}
                <span>
                  5. Rule Evaluation & Baseline — {hasSessions ? `${riskData?.total_findings} findings` : 'No applicable security observations'}
                </span>
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
                {!hasSessions
                  ? 'No mail sessions were reconstructed for rule evaluation.'
                  : 'No security rule violations observed for this capture.'}
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
              <span>Sessions ({riskData?.total_sessions ?? 0})</span>
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
              <span>Findings ({riskData?.total_findings ?? 0})</span>
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
              <span>Drift ({riskData?.drift_count ?? 0})</span>
            </div>
            <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </div>
  );
};

