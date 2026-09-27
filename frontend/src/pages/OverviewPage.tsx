import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Layers,
  TrendingDown,
  Clock,
  ArrowRight,
  FileCheck,
} from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { riskApi, findingsApi } from '../api/services';
import type { RiskSummaryResponse, FindingRead } from '../types/api';
import { StatCard } from '../components/common/StatCard';
import { RiskBandBadge, SeverityBadge } from '../components/common/Badge';
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
      <EmptyState
        title="No Active Capture Context"
        subtitle="Please upload or select a network packet capture file to view forensic security posture."
      />
    );
  }

  if (isLoading) {
    return <LoadingState message="Loading security posture summary and findings..." />;
  }

  if (errorMsg) {
    return <ErrorState message={errorMsg} />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header Banner */}
      <div
        className="card"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2>{activeCapture?.filename || 'Active Investigation'}</h2>
            <RiskBandBadge band={riskData?.risk_band} />
          </div>
          <div className="hash" style={{ marginTop: '4px' }}>
            SHA-256: {activeCapture?.sha256_hash}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
              Overall Risk Score
            </div>
            <div
              style={{
                fontSize: '2rem',
                fontWeight: 700,
                color:
                  (riskData?.overall_risk_score || 0) >= 60
                    ? 'var(--color-high)'
                    : (riskData?.overall_risk_score || 0) >= 40
                    ? 'var(--color-warning)'
                    : 'var(--color-success)',
              }}
            >
              {riskData?.overall_risk_score !== undefined
                ? riskData.overall_risk_score.toFixed(1)
                : 'INSUFFICIENT DATA'}
              <span style={{ fontSize: '1rem', color: 'var(--color-text-muted)' }}> / 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid-stats">
        <StatCard
          label="Mail Sessions"
          value={riskData?.total_sessions ?? 0}
          subtext={`${riskData?.high_risk_session_count ?? 0} high-risk`}
          icon={<Layers size={24} />}
          accentColor="var(--color-accent)"
        />
        <StatCard
          label="Rule Findings"
          value={riskData?.total_findings ?? 0}
          subtext="Security violations"
          icon={<ShieldAlert size={24} />}
          accentColor="var(--color-high)"
        />
        <StatCard
          label="Drift Events"
          value={riskData?.drift_count ?? 0}
          subtext="Baseline deltas"
          icon={<TrendingDown size={24} />}
          accentColor="var(--color-warning)"
        />
        <StatCard
          label="Packets Analyzed"
          value={activeCapture?.total_packets.toLocaleString() ?? 0}
          subtext={`${((activeCapture?.file_size_bytes ?? 0) / 1024).toFixed(0)} KB`}
          icon={<FileCheck size={24} />}
          accentColor="var(--color-info)"
        />
      </div>

      {/* Main Breakdown Grid */}
      <div className="grid-content-2">
        {/* Severity Distribution Card */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3>Finding Severity Distribution</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => {
              const count = riskData?.severity_distribution[sev] || 0;
              const total = riskData?.total_findings || 1;
              const pct = Math.round((count / total) * 100);
              const colorMap: Record<string, string> = {
                CRITICAL: 'var(--color-critical)',
                HIGH: 'var(--color-high)',
                MEDIUM: 'var(--color-warning)',
                LOW: 'var(--color-success)',
                INFO: 'var(--color-accent)',
              };

              return (
                <div key={sev}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '4px' }}>
                    <span style={{ fontWeight: 600, color: colorMap[sev] }}>{sev}</span>
                    <span className="mono">{count} ({pct}%)</span>
                  </div>
                  <div style={{ height: '6px', background: 'var(--color-bg-primary)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        background: colorMap[sev],
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Quick Navigation / Forensic Links */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h3>Forensic Investigation Workspaces</h3>
            <p style={{ fontSize: '0.875rem', marginTop: '4px' }}>
              Deep-dive into network sessions, evidence frames, infrastructure identity, and cryptographic drift.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '16px' }}>
            <Link to="/sessions" className="btn btn--secondary" style={{ justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={16} /> Reconstructed Sessions ({riskData?.total_sessions})
              </span>
              <ArrowRight size={16} />
            </Link>

            <Link to="/findings" className="btn btn--secondary" style={{ justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={16} /> Security Findings ({riskData?.total_findings})
              </span>
              <ArrowRight size={16} />
            </Link>

            <Link to="/drifts" className="btn btn--secondary" style={{ justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <TrendingDown size={16} /> Cryptographic Drift ({riskData?.drift_count})
              </span>
              <ArrowRight size={16} />
            </Link>

            <Link to="/timeline" className="btn btn--secondary" style={{ justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Clock size={16} /> Forensic Network Timeline
              </span>
              <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </div>

      {/* Recent High-Priority Findings */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3>High-Priority Security Findings</h3>
          <Link to="/findings" className="btn btn--ghost" style={{ fontSize: '0.8rem' }}>
            View All ({riskData?.total_findings}) <ArrowRight size={14} />
          </Link>
        </div>

        {recentFindings.length === 0 ? (
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', padding: '16px 0' }}>
            No security findings observed for this capture.
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Title</th>
                <th>Evidence Items</th>
              </tr>
            </thead>
            <tbody>
              {recentFindings.map((f) => (
                <tr key={f.id}>
                  <td className="mono">{f.rule_id}</td>
                  <td>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>{f.category}</td>
                  <td>
                    <strong>{f.title}</strong>
                    <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                      {f.description.substring(0, 90)}...
                    </div>
                  </td>
                  <td className="mono">{f.evidence.length} fields</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
