import React, { useState, useEffect } from 'react';
import { Server, RefreshCw } from 'lucide-react';
import { infrastructureApi } from '../api/services';
import type { InfrastructureIdentityRead, PaginatedResponse } from '../types/api';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const InfrastructurePage: React.FC = () => {
  const [data, setData] = useState<PaginatedResponse<InfrastructureIdentityRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedIdentity, setSelectedIdentity] = useState<InfrastructureIdentityRead | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchInfra = async (currentPage = page) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await infrastructureApi.list(currentPage, 20);
      setData(res);
      if (res.items.length > 0 && !selectedIdentity) {
        setSelectedIdentity(res.items[0]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch infrastructure identities.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchInfra(page);
  }, [page]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Infrastructure Identity Baselines</h2>
          <p>Stable mail server infrastructure identities tracked across captures (resilient to certificate rotation).</p>
        </div>
        <button onClick={() => fetchInfra(page)} className="btn btn--ghost">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {isLoading ? (
        <LoadingState message="Fetching infrastructure identities and baseline profiles..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchInfra(page)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Infrastructure Identities"
          subtitle="No server identities have been evaluated yet in the database."
          icon={<Server size={40} />}
        />
      ) : (
        <div className="grid-content-2">
          {/* Identity List Table */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Server Endpoint</th>
                  <th>Protocol</th>
                  <th>Hostname</th>
                  <th>Drifts</th>
                  <th>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((inf) => (
                  <tr
                    key={inf.id}
                    onClick={() => setSelectedIdentity(inf)}
                    style={{
                      cursor: 'pointer',
                      background: selectedIdentity?.id === inf.id ? 'var(--color-surface-hover)' : undefined,
                    }}
                  >
                    <td className="mono" style={{ fontWeight: 600 }}>
                      {inf.ip_address}:{inf.port}
                    </td>
                    <td>{inf.protocol}</td>
                    <td>{inf.hostname || '-'}</td>
                    <td className="mono">{inf.drift_events?.length || 0}</td>
                    <td className="mono" style={{ fontWeight: 600 }}>
                      <span
                        style={{
                          color: (inf.current_risk_score || 0) >= 40 ? 'var(--color-high)' : 'var(--color-success)',
                        }}
                      >
                        {inf.current_risk_score !== null && inf.current_risk_score !== undefined
                          ? inf.current_risk_score.toFixed(1)
                          : 'N/A'}
                      </span>
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

          {/* Identity Detail Inspector */}
          {selectedIdentity ? (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                  Infrastructure Identity
                </div>
                <h3 className="mono" style={{ color: 'var(--color-accent-cyan)', marginTop: '2px' }}>
                  {selectedIdentity.ip_address}:{selectedIdentity.port} ({selectedIdentity.protocol})
                </h3>
              </div>

              <div className="grid-content-2" style={{ gap: '12px', fontSize: '0.85rem' }}>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Hostname:</span><br />
                  <strong>{selectedIdentity.hostname || 'None'}</strong>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Identity Key:</span><br />
                  <span className="hash">{selectedIdentity.identity_key}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>First Seen:</span><br />
                  <span className="mono">{new Date(selectedIdentity.first_seen_at).toLocaleString()}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Last Seen:</span><br />
                  <span className="mono">{new Date(selectedIdentity.last_seen_at).toLocaleString()}</span>
                </div>
              </div>

              {/* Baseline Profile JSON */}
              <div>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                  Cryptographic Baseline Profile:
                </span>
                <pre style={{ marginTop: '6px', fontSize: '0.75rem', maxHeight: '180px' }}>
                  {selectedIdentity.active_profile_json
                    ? JSON.stringify(JSON.parse(selectedIdentity.active_profile_json), null, 2)
                    : 'No active profile recorded'}
                </pre>
              </div>

              {/* Observed Drift History */}
              <div>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                  Observed Drift Events ({selectedIdentity.drift_events?.length || 0}):
                </span>

                {(!selectedIdentity.drift_events || selectedIdentity.drift_events.length === 0) ? (
                  <div style={{ fontSize: '0.85rem', color: 'var(--color-text-tertiary)', marginTop: '6px' }}>
                    No baseline cryptographic drift events recorded for this infrastructure identity.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                    {selectedIdentity.drift_events.map((d) => (
                      <div
                        key={d.id}
                        style={{
                          padding: '8px 12px',
                          background: 'var(--color-bg-secondary)',
                          borderLeft: '3px solid var(--color-warning)',
                          borderRadius: '4px',
                          fontSize: '0.8rem',
                        }}
                      >
                        <div style={{ fontWeight: 600, color: 'var(--color-warning)' }}>{d.event_type}</div>
                        <div style={{ color: 'var(--color-text-secondary)', marginTop: '2px' }}>{d.delta_description}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              Select an infrastructure identity row to inspect baseline profile and drift history.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
