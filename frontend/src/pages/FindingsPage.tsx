import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ShieldAlert, Filter, Activity, Eye, RefreshCw } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { findingsApi, type FindingFilterParams } from '../api/services';
import type { FindingRead, PaginatedResponse } from '../types/api';
import { SeverityBadge } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const FindingsPage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const [searchParams] = useSearchParams();
  const [data, setData] = useState<PaginatedResponse<FindingRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedFinding, setSelectedFinding] = useState<FindingRead | null>(null);
  const [filters, setFilters] = useState<FindingFilterParams>({
    severity: searchParams.get('severity') || undefined,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchFindings = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await findingsApi.list({
        job_id: activeJob?.id,
        page: currentPage,
        page_size: 20,
        ...currentFilters,
      });
      setData(res);
      if (res.items.length > 0 && !selectedFinding) {
        setSelectedFinding(res.items[0]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch security findings.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings(page, filters);
  }, [page, activeJob]);

  const handleFilterChange = (key: keyof FindingFilterParams, value: any) => {
    const nextFilters = { ...filters, [key]: value || undefined };
    setFilters(nextFilters);
    setPage(1);
    fetchFindings(1, nextFilters);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Security Rule Findings</h2>
          <p>Deterministic security findings evaluated by SecureMailScope Phase 5 Rule Engine.</p>
        </div>
        <button onClick={() => fetchFindings(page, filters)} className="btn btn--ghost">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="card" style={{ padding: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', fontSize: '0.85rem', fontWeight: 600 }}>
          <Filter size={16} style={{ color: 'var(--color-accent-cyan)' }} /> Finding Filters
        </div>

        <div className="grid-content" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Severity
            </label>
            <select
              className="input"
              value={filters.severity || ''}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Category
            </label>
            <select
              className="input"
              value={filters.category || ''}
              onChange={(e) => handleFilterChange('category', e.target.value)}
            >
              <option value="">All Categories</option>
              <option value="TLS_CRYPTO">TLS & Cipher Suites</option>
              <option value="X509_CERT">X.509 Certificates</option>
              <option value="STARTTLS">STARTTLS Negotiation</option>
              <option value="PROTOCOL_ANOMALY">Protocol Anomalies</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Rule ID
            </label>
            <input
              type="text"
              placeholder="e.g. CRYPT-001"
              className="input"
              value={filters.rule_id || ''}
              onChange={(e) => handleFilterChange('rule_id', e.target.value)}
            />
          </div>
        </div>
      </div>

      {isLoading ? (
        <LoadingState message="Fetching rule findings..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchFindings(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Security Findings Observed"
          subtitle="No rule violations were detected for the selected capture and search filters."
          icon={<ShieldAlert size={40} />}
        />
      ) : (
        <div className="grid-content-2">
          {/* Findings Table List */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Sev</th>
                  <th>Title</th>
                  <th>Score Impact</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    style={{
                      cursor: 'pointer',
                      background: selectedFinding?.id === f.id ? 'var(--color-surface-hover)' : undefined,
                    }}
                  >
                    <td className="mono">{f.rule_id}</td>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <strong style={{ fontSize: '0.85rem' }}>{f.title}</strong>
                    </td>
                    <td className="mono" style={{ color: 'var(--color-high)', fontWeight: 600 }}>
                      +{f.score_contribution}
                    </td>
                    <td>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="btn btn--ghost"
                        style={{ padding: '2px 6px', fontSize: '0.75rem' }}
                      >
                        <Eye size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <Pagination
              page={data.page}
              totalPages={data.total_pages}
              totalItems={data.total}
              pageSize={data.page_size}
              onPageChange={(p) => setPage(p)}
            />
          </div>

          {/* Detailed Inspector Drawer */}
          {selectedFinding ? (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--color-accent-cyan)' }}>
                      {selectedFinding.rule_id}
                    </span>
                    <SeverityBadge severity={selectedFinding.severity} />
                  </div>
                  <h3 style={{ marginTop: '4px' }}>{selectedFinding.title}</h3>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>Score Impact</div>
                  <div className="mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-high)' }}>
                    +{selectedFinding.score_contribution} pts
                  </div>
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                  Category & Confidence:
                </span>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, marginTop: '2px' }}>
                  {selectedFinding.category} | Confidence: {selectedFinding.confidence}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                  Observed Violation Details:
                </span>
                <p style={{ fontSize: '0.875rem', marginTop: '4px', color: 'var(--color-text)' }}>
                  {selectedFinding.description}
                </p>
              </div>

              {selectedFinding.remediation_recommendation && (
                <div style={{ background: 'var(--color-bg-secondary)', padding: '12px', borderRadius: '6px', borderLeft: '3px solid var(--color-accent-cyan)' }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-accent-cyan)', marginBottom: '4px' }}>
                    Recommended Remediation:
                  </div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
                    {selectedFinding.remediation_recommendation}
                  </div>
                </div>
              )}

              {/* Evidence Lineage Attached */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                    Attached Forensic Packet Evidence ({selectedFinding.evidence.length}):
                  </span>
                  <Link
                    to={`/evidence?finding_id=${selectedFinding.id}`}
                    className="btn btn--secondary"
                    style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                  >
                    <Activity size={12} /> Full Lineage Explorer
                  </Link>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {selectedFinding.evidence.map((ev) => (
                    <div
                      key={ev.id}
                      style={{
                        padding: '10px 12px',
                        background: 'var(--color-bg-secondary)',
                        borderRadius: '4px',
                        fontSize: '0.8rem',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span className="mono" style={{ color: 'var(--color-accent-cyan)', fontWeight: 600 }}>
                          Frame #{ev.frame_number} [{ev.protocol_layer}]
                        </span>
                        <span style={{ color: 'var(--color-text-tertiary)' }}>{ev.field_name}</span>
                      </div>
                      <div className="mono" style={{ marginTop: '4px', color: 'var(--color-text)' }}>
                        Observed Value: "{ev.observed_value}"
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {selectedFinding.session_id && (
                <Link
                  to={`/sessions/${selectedFinding.session_id}`}
                  className="btn btn--primary"
                  style={{ justifyContent: 'center', marginTop: '8px' }}
                >
                  Inspect Associated Mail Session
                </Link>
              )}
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-tertiary)' }}>
              Select a finding row to view forensic description and attached packet evidence.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
