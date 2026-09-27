import React, { useState, useEffect } from 'react';
import { TrendingDown, RefreshCw } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { driftsApi, type DriftFilterParams } from '../api/services';
import type { DriftEventRead, PaginatedResponse } from '../types/api';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const DriftPage: React.FC = () => {
  const { activeCapture, activeJob } = useWorkspace();
  const [data, setData] = useState<PaginatedResponse<DriftEventRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedDrift, setSelectedDrift] = useState<DriftEventRead | null>(null);
  const [filters] = useState<DriftFilterParams>({});
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchDrifts = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await driftsApi.list({
        job_id: activeJob?.id,
        capture_id: activeCapture?.id,
        page: currentPage,
        page_size: 20,
        ...currentFilters,
      });
      setData(res);
      if (res.items.length > 0 && !selectedDrift) {
        setSelectedDrift(res.items[0]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch cryptographic drift events.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDrifts(page, filters);
  }, [page, activeJob, activeCapture]);

  const parseStateJson = (jsonStr?: string | null) => {
    if (!jsonStr) return null;
    try {
      return JSON.parse(jsonStr);
    } catch {
      return jsonStr;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Cryptographic Baseline Drift Analysis</h2>
          <p>Investigate behavioral state changes and configuration downgrades detected across infrastructure identities.</p>
        </div>
        <button onClick={() => fetchDrifts(page, filters)} className="btn btn--ghost">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {isLoading ? (
        <LoadingState message="Analyzing cryptographic drift events..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchDrifts(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Cryptographic Drift Observed"
          subtitle="No behavioral or security baseline drift events were detected for this analysis context."
          icon={<TrendingDown size={40} />}
        />
      ) : (
        <div className="grid-content-2">
          {/* Drift Events List Table */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th>Delta Description</th>
                  <th>Risk Delta</th>
                  <th>Detected At</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((d) => (
                  <tr
                    key={d.id}
                    onClick={() => setSelectedDrift(d)}
                    style={{
                      cursor: 'pointer',
                      background: selectedDrift?.id === d.id ? 'var(--color-surface-hover)' : undefined,
                    }}
                  >
                    <td>
                      <span
                        style={{
                          fontWeight: 600,
                          fontSize: '0.8rem',
                          color: 'var(--color-warning)',
                        }}
                      >
                        {d.event_type}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{d.delta_description}</td>
                    <td className="mono" style={{ color: 'var(--color-high)', fontWeight: 600 }}>
                      +{d.risk_delta ?? 0}
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                      {new Date(d.detected_at).toLocaleTimeString()}
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

          {/* Side-by-Side Before vs. After Inspector */}
          {selectedDrift ? (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                  Observed Drift Event
                </div>
                <h3 style={{ color: 'var(--color-warning)', marginTop: '2px' }}>{selectedDrift.event_type}</h3>
                <p style={{ marginTop: '4px', fontSize: '0.875rem' }}>{selectedDrift.delta_description}</p>
              </div>

              {/* Forensic Before vs After */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                {/* BEFORE */}
                <div
                  style={{
                    padding: '12px',
                    background: 'var(--color-bg-secondary)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                  }}
                >
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-success)', textTransform: 'uppercase', marginBottom: '8px' }}>
                    PREVIOUS BASELINE
                  </div>
                  <pre style={{ fontSize: '0.75rem', margin: 0 }}>
                    {JSON.stringify(parseStateJson(selectedDrift.previous_state_json), null, 2) || 'N/A (First observation)'}
                  </pre>
                </div>

                {/* AFTER */}
                <div
                  style={{
                    padding: '12px',
                    background: 'var(--color-bg-secondary)',
                    border: '1px solid var(--color-high)',
                    borderRadius: '6px',
                  }}
                >
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-high)', textTransform: 'uppercase', marginBottom: '8px' }}>
                    CURRENT OBSERVATION
                  </div>
                  <pre style={{ fontSize: '0.75rem', margin: 0 }}>
                    {JSON.stringify(parseStateJson(selectedDrift.new_state_json), null, 2) || 'N/A'}
                  </pre>
                </div>
              </div>

              <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                Identity ID: <span className="mono">{selectedDrift.infrastructure_id}</span>
              </div>
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              Select a drift event to inspect side-by-side Before/After state deltas.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
