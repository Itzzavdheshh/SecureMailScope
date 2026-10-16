import React, { useEffect, useState, useCallback } from 'react';
import { Brain, AlertTriangle, CheckCircle2, Clock, ChevronDown, ChevronRight, Info, BarChart2, Cpu } from 'lucide-react';
import { behaviorApi } from '../api/services';
import { useWorkspace } from '../context/WorkspaceContext';
import type { BehavioralAnalysisRead, BehavioralAnomaly } from '../types/api';

// ── Significance badge colours ───────────────────────────────────────────────

const SIG_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  HIGH:   { bg: 'rgba(239,68,68,0.15)',   text: '#f87171', label: 'HIGH' },
  MEDIUM: { bg: 'rgba(234,179,8,0.15)',   text: '#facc15', label: 'MEDIUM' },
  LOW:    { bg: 'rgba(59,130,246,0.15)',  text: '#60a5fa', label: 'LOW' },
  NONE:   { bg: 'rgba(107,114,128,0.15)', text: '#9ca3af', label: 'NONE' },
};

const BASELINE_COLORS: Record<string, string> = {
  NO_BASELINE:  '#6b7280',
  PROVISIONAL:  '#f59e0b',
  ESTABLISHED:  '#22c55e',
  TRUSTED:      '#3b82f6',
};

// ── Sub-components ────────────────────────────────────────────────────────────

const SignificanceBadge: React.FC<{ sig: string }> = ({ sig }) => {
  const c = SIG_COLORS[sig] ?? SIG_COLORS.NONE;
  return (
    <span style={{
      background: c.bg,
      color: c.text,
      border: `1px solid ${c.text}30`,
      borderRadius: 4,
      padding: '1px 8px',
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.05em',
    }}>
      {c.label}
    </span>
  );
};

const AnomalyCard: React.FC<{ anomaly: BehavioralAnomaly }> = ({ anomaly }) => (
  <div style={{
    background: 'rgba(255,255,255,0.03)',
    border: '1px solid rgba(255,255,255,0.07)',
    borderRadius: 8,
    padding: '12px 16px',
    marginBottom: 8,
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
      <SignificanceBadge sig={anomaly.significance} />
      <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{anomaly.feature}</span>
    </div>
    <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 4 }}>
      {anomaly.change_description}
    </div>
    <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.5 }}>
      {anomaly.reason}
    </div>
    {anomaly.stat_zscore !== null && (
      <div style={{ marginTop: 6, fontSize: 12, color: '#475569' }}>
        <span style={{ color: '#64748b' }}>Z-score:</span>{' '}
        <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{anomaly.stat_zscore?.toFixed(3)}</span>
        {anomaly.stat_sample_count !== null && (
          <span style={{ marginLeft: 12, color: '#64748b' }}>n={anomaly.stat_sample_count}</span>
        )}
      </div>
    )}
  </div>
);

const StatPanel: React.FC<{ analysis: BehavioralAnalysisRead }> = ({ analysis }) => {
  const rs = analysis.risk_stat_analysis;
  const ifr = analysis.isolation_forest;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
      {/* Risk Score Stats */}
      <div style={{
        background: 'rgba(59,130,246,0.06)',
        border: '1px solid rgba(59,130,246,0.15)',
        borderRadius: 8,
        padding: 14,
      }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#60a5fa', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          <BarChart2 size={12} style={{ marginRight: 5, display: 'inline' }} />
          Risk Score Analysis
        </div>
        {rs ? (
          <>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>
              Method: <span style={{ color: '#e2e8f0', fontFamily: 'monospace' }}>{rs.method}</span>
              {' · '}Status: <span style={{ color: rs.method_status === 'COMPLETED' ? '#22c55e' : '#f59e0b' }}>{rs.method_status}</span>
            </div>
            {rs.method_status === 'COMPLETED' && (
              <>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Baseline mean: <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{rs.baseline_mean?.toFixed(2) ?? 'N/A'}</span>
                  {' '}±{' '}<span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{rs.baseline_std?.toFixed(2) ?? 'N/A'}</span>
                </div>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Observed: <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{rs.observed_value?.toFixed(2) ?? 'N/A'}</span>
                  {' · '}Z: <span style={{ color: rs.is_anomalous ? '#f87171' : '#94a3b8', fontFamily: 'monospace' }}>{rs.zscore?.toFixed(3) ?? 'N/A'}</span>
                  {rs.is_anomalous && <span style={{ marginLeft: 6, color: '#f87171', fontWeight: 700 }}>⚠ Anomalous</span>}
                </div>
                <div style={{ fontSize: 11, color: '#475569', marginTop: 6, lineHeight: 1.4 }}>{rs.interpretation}</div>
              </>
            )}
            {rs.method_status === 'INSUFFICIENT_DATA' && (
              <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 4 }}>{rs.interpretation}</div>
            )}
          </>
        ) : (
          <div style={{ fontSize: 12, color: '#475569' }}>No statistical risk analysis available.</div>
        )}
      </div>

      {/* Isolation Forest */}
      <div style={{
        background: 'rgba(139,92,246,0.06)',
        border: '1px solid rgba(139,92,246,0.15)',
        borderRadius: 8,
        padding: 14,
      }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          <Cpu size={12} style={{ marginRight: 5, display: 'inline' }} />
          Isolation Forest
        </div>
        {ifr ? (
          <>
            <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>
              Status: <span style={{ color: ifr.method_status === 'COMPLETED' ? '#22c55e' : '#f59e0b' }}>{ifr.method_status}</span>
              {' · '}n={ifr.observation_count} (min: {ifr.min_required})
            </div>
            {ifr.method_status === 'COMPLETED' && (
              <>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Anomaly score: <span style={{ color: ifr.is_anomalous ? '#f87171' : '#94a3b8', fontFamily: 'monospace' }}>
                    {ifr.normalized_anomaly_score?.toFixed(4) ?? 'N/A'}
                  </span>
                  {ifr.is_anomalous && <span style={{ marginLeft: 6, color: '#f87171', fontWeight: 700 }}>⚠ Flagged</span>}
                </div>
                <div style={{ fontSize: 11, color: '#475569', marginTop: 6, lineHeight: 1.4 }}>{ifr.interpretation}</div>
              </>
            )}
            {ifr.method_status !== 'COMPLETED' && (
              <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 4 }}>{ifr.interpretation}</div>
            )}
          </>
        ) : (
          <div style={{ fontSize: 12, color: '#475569' }}>Isolation Forest not executed for this observation.</div>
        )}
      </div>
    </div>
  );
};

interface AnalysisCardProps {
  analysis: BehavioralAnalysisRead;
}

const AnalysisCard: React.FC<AnalysisCardProps> = ({ analysis }) => {
  const [expanded, setExpanded] = useState(false);
  const isInsufficient = analysis.overall_status === 'INSUFFICIENT_EVIDENCE';
  const statusColor = isInsufficient ? '#f59e0b' : analysis.significant_deviation_detected ? '#f87171' : '#22c55e';
  const statusLabel = isInsufficient ? 'INSUFFICIENT DATA' : analysis.significant_deviation_detected ? 'DEVIATION DETECTED' : 'NO DEVIATION';
  const baselineColor = BASELINE_COLORS[analysis.baseline_status] ?? '#6b7280';

  return (
    <div style={{
      background: 'var(--panel)',
      border: `1px solid ${analysis.significant_deviation_detected ? 'rgba(248,113,113,0.2)' : 'rgba(255,255,255,0.06)'}`,
      borderRadius: 10,
      marginBottom: 10,
      overflow: 'hidden',
    }}>
      {/* Header row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '14px 18px',
          cursor: 'pointer',
          userSelect: 'none',
        }}
        onClick={() => setExpanded(e => !e)}
        id={`behavior-card-${analysis.id}`}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 0 }}>
          {/* Status indicator */}
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: statusColor, flexShrink: 0,
          }} />
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {analysis.identity_key}
            </div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
              Session {analysis.session_id?.slice(0, 8) ?? 'N/A'} · {new Date(analysis.analyzed_at).toLocaleTimeString()}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          {/* Baseline status */}
          <span style={{
            fontSize: 10, fontWeight: 700, letterSpacing: '0.06em',
            color: baselineColor, background: `${baselineColor}18`,
            border: `1px solid ${baselineColor}30`,
            borderRadius: 4, padding: '2px 7px',
          }}>
            {analysis.baseline_status}
          </span>
          {/* Overall status */}
          <span style={{
            fontSize: 10, fontWeight: 700, letterSpacing: '0.06em',
            color: statusColor, background: `${statusColor}18`,
            border: `1px solid ${statusColor}30`,
            borderRadius: 4, padding: '2px 7px',
          }}>
            {statusLabel}
          </span>
          {/* Anomaly count */}
          {analysis.anomaly_count > 0 && (
            <span style={{
              fontSize: 11, fontWeight: 700, color: '#f87171',
              background: 'rgba(239,68,68,0.12)', borderRadius: 4, padding: '2px 8px',
            }}>
              {analysis.anomaly_count} anomal{analysis.anomaly_count === 1 ? 'y' : 'ies'}
            </span>
          )}
          {expanded ? <ChevronDown size={14} color="#64748b" /> : <ChevronRight size={14} color="#64748b" />}
        </div>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div style={{ padding: '0 18px 18px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          {/* Deviation summary */}
          <div style={{
            background: 'rgba(255,255,255,0.03)',
            borderRadius: 8, padding: '10px 14px', marginTop: 12,
            fontSize: 13, color: '#94a3b8', lineHeight: 1.6,
          }}>
            {analysis.deviation_summary}
          </div>

          {/* Anomalies */}
          {analysis.anomalies.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                Detected Deviations
              </div>
              {analysis.anomalies.map((a, i) => (
                <AnomalyCard key={i} anomaly={a} />
              ))}
            </div>
          )}

          {/* Statistical analysis panels */}
          <StatPanel analysis={analysis} />

          {/* Limitations */}
          {analysis.limitations.length > 0 && (
            <div style={{
              marginTop: 14,
              background: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.05)',
              borderRadius: 8, padding: '10px 14px',
            }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                Analytical Limitations
              </div>
              {analysis.limitations.map((l, i) => (
                <div key={i} style={{ fontSize: 12, color: '#64748b', display: 'flex', gap: 6, marginBottom: 3 }}>
                  <Info size={12} style={{ marginTop: 2, flexShrink: 0, color: '#475569' }} />
                  {l}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Main Page ─────────────────────────────────────────────────────────────────

export const BehaviorPage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const [analyses, setAnalyses] = useState<BehavioralAnalysisRead[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [significantOnly, setSignificantOnly] = useState(false);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 50;

  // Summary stats from the list
  const sigCount = analyses.filter(a => a.significant_deviation_detected).length;
  const insufficientCount = analyses.filter(a => a.overall_status === 'INSUFFICIENT_EVIDENCE').length;
  const totalAnomalies = analyses.reduce((s, a) => s + a.anomaly_count, 0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, unknown> = { page, page_size: PAGE_SIZE };
      if (activeJob?.id) params.job_id = activeJob.id;
      if (significantOnly) params.significant_only = true;

      const data = await behaviorApi.list(params as Parameters<typeof behaviorApi.list>[0]);
      setAnalyses(data.items);
      setTotal(data.total);
    } catch (e) {
      setError('Failed to load behavioural analysis results. Ensure a PCAP has been analysed first.');
    } finally {
      setLoading(false);
    }
  }, [activeJob, page, significantOnly]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="page-container">
      {/* Page header */}
      <div className="page-header">
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Brain size={22} style={{ color: '#a78bfa' }} />
            Behavioural Analysis
          </h1>
          <p className="page-subtitle">
            Phase 10 — Explainable cryptographic deviation analysis relative to established infrastructure baselines.
            No attacker attribution. Based solely on passively observed evidence.
          </p>
        </div>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Total Analyses', value: total, icon: <Brain size={16} />, color: '#a78bfa' },
          { label: 'Significant Deviations', value: sigCount, icon: <AlertTriangle size={16} />, color: '#f87171' },
          { label: 'Insufficient Data', value: insufficientCount, icon: <Clock size={16} />, color: '#f59e0b' },
          { label: 'Total Anomalies', value: totalAnomalies, icon: <BarChart2 size={16} />, color: '#60a5fa' },
          { label: 'No Deviation', value: analyses.filter(a => !a.significant_deviation_detected && a.overall_status !== 'INSUFFICIENT_EVIDENCE').length, icon: <CheckCircle2 size={16} />, color: '#22c55e' },
        ].map(card => (
          <div key={card.label} style={{
            background: 'var(--panel)',
            border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 10,
            padding: '14px 18px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, color: card.color }}>
              {card.icon}
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em' }}>{card.label}</span>
            </div>
            <div style={{ fontSize: 26, fontWeight: 700, color: '#f1f5f9', fontVariantNumeric: 'tabular-nums' }}>
              {loading ? '—' : card.value}
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16,
        flexWrap: 'wrap',
      }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#94a3b8', cursor: 'pointer' }}>
          <input
            type="checkbox"
            id="significant-only-filter"
            checked={significantOnly}
            onChange={e => { setSignificantOnly(e.target.checked); setPage(1); }}
            style={{ accentColor: '#f87171' }}
          />
          Show significant deviations only
        </label>
        {activeJob && (
          <span style={{
            fontSize: 11, color: '#64748b', background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.07)', borderRadius: 5, padding: '3px 10px',
          }}>
            Filtered to job: {activeJob.id.slice(0, 8)}…
          </span>
        )}
        <button
          id="refresh-behavior-btn"
          onClick={load}
          style={{
            marginLeft: 'auto',
            background: 'rgba(167,139,250,0.1)',
            border: '1px solid rgba(167,139,250,0.25)',
            color: '#a78bfa', borderRadius: 6,
            padding: '6px 14px', fontSize: 12, cursor: 'pointer',
          }}
        >
          Refresh
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div style={{
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.25)',
          borderRadius: 8, padding: '12px 16px', marginBottom: 16,
          color: '#f87171', fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{ textAlign: 'center', color: '#475569', padding: 48, fontSize: 13 }}>
          Loading behavioural analysis results…
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && analyses.length === 0 && (
        <div style={{
          textAlign: 'center', color: '#475569', padding: 64,
          background: 'var(--panel)',
          border: '1px solid rgba(255,255,255,0.05)',
          borderRadius: 10,
        }}>
          <Brain size={36} style={{ opacity: 0.3, marginBottom: 14 }} />
          <div style={{ fontSize: 15, fontWeight: 600, color: '#64748b', marginBottom: 6 }}>
            No behavioural analysis results found
          </div>
          <div style={{ fontSize: 13, maxWidth: 420, margin: '0 auto', lineHeight: 1.6 }}>
            Behavioural analysis runs automatically during PCAP pipeline execution.
            Upload and analyse a PCAP to generate results.
            {significantOnly && ' Try removing the "significant only" filter.'}
          </div>
        </div>
      )}

      {/* Analysis cards */}
      {!loading && !error && analyses.length > 0 && (
        <div>
          {analyses.map(a => (
            <AnalysisCard key={a.id} analysis={a} />
          ))}

          {/* Pagination */}
          {total > PAGE_SIZE && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginTop: 20 }}>
              <button
                id="behavior-prev-page-btn"
                disabled={page <= 1}
                onClick={() => setPage(p => p - 1)}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: page <= 1 ? '#475569' : '#94a3b8',
                  borderRadius: 6, padding: '6px 16px', fontSize: 12, cursor: page <= 1 ? 'not-allowed' : 'pointer',
                }}
              >
                Previous
              </button>
              <span style={{ fontSize: 12, color: '#64748b' }}>
                Page {page} · {total} total
              </span>
              <button
                id="behavior-next-page-btn"
                disabled={page * PAGE_SIZE >= total}
                onClick={() => setPage(p => p + 1)}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  color: page * PAGE_SIZE >= total ? '#475569' : '#94a3b8',
                  borderRadius: 6, padding: '6px 16px', fontSize: 12, cursor: page * PAGE_SIZE >= total ? 'not-allowed' : 'pointer',
                }}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
