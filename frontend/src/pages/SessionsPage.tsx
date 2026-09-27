import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layers, Filter, Eye, RefreshCw } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { sessionsApi, type SessionFilterParams } from '../api/services';
import type { EmailSessionRead, PaginatedResponse } from '../types/api';
import { StarttlsStateBadge } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const SessionsPage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const [data, setData] = useState<PaginatedResponse<EmailSessionRead> | null>(null);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<SessionFilterParams>({});
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const navigate = useNavigate();

  const fetchSessions = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await sessionsApi.list({
        job_id: activeJob?.id,
        page: currentPage,
        page_size: 20,
        ...currentFilters,
      });
      setData(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch email sessions.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions(page, filters);
  }, [page, activeJob]);

  const handleFilterChange = (key: keyof SessionFilterParams, value: any) => {
    const nextFilters = { ...filters, [key]: value || undefined };
    setFilters(nextFilters);
    setPage(1);
    fetchSessions(1, nextFilters);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Reconstructed Mail Sessions</h2>
          <p>Inspect forensic email sessions, STARTTLS negotiation, TLS parameters, and risk scores.</p>
        </div>
        <button onClick={() => fetchSessions(page, filters)} className="btn btn--ghost">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="card" style={{ padding: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', fontSize: '0.85rem', fontWeight: 600 }}>
          <Filter size={16} style={{ color: 'var(--color-accent-cyan)' }} /> Server-Side Session Filters
        </div>

        <div className="grid-content" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Protocol
            </label>
            <select
              className="input"
              value={filters.protocol || ''}
              onChange={(e) => handleFilterChange('protocol', e.target.value)}
            >
              <option value="">All Protocols</option>
              <option value="SMTP">SMTP</option>
              <option value="IMAP">IMAP</option>
              <option value="POP3">POP3</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              STARTTLS State
            </label>
            <select
              className="input"
              value={filters.starttls_state || ''}
              onChange={(e) => handleFilterChange('starttls_state', e.target.value)}
            >
              <option value="">All States</option>
              <option value="NOT_OBSERVED">NOT OBSERVED</option>
              <option value="ADVERTISED">ADVERTISED</option>
              <option value="ATTEMPTED">ATTEMPTED</option>
              <option value="ESTABLISHED">ESTABLISHED</option>
              <option value="REJECTED">REJECTED</option>
              <option value="DISABLED">DISABLED</option>
              <option value="CLEARTEXT_FALLBACK">CLEARTEXT FALLBACK</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              TLS Version
            </label>
            <select
              className="input"
              value={filters.tls_version || ''}
              onChange={(e) => handleFilterChange('tls_version', e.target.value)}
            >
              <option value="">All Versions</option>
              <option value="TLS 1.3">TLS 1.3</option>
              <option value="TLS 1.2">TLS 1.2</option>
              <option value="TLS 1.1">TLS 1.1</option>
              <option value="TLS 1.0">TLS 1.0</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Server IP / Host
            </label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.1"
              className="input"
              value={filters.server_ip || filters.hostname || ''}
              onChange={(e) => handleFilterChange('server_ip', e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Main Table */}
      {isLoading ? (
        <LoadingState message="Fetching reconstructed mail sessions..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchSessions(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Mail Sessions Observed"
          subtitle="No email sessions were observed matching the selected job or filter criteria."
          icon={<Layers size={40} />}
        />
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Index</th>
                <th>Client Endpoint</th>
                <th>Server Endpoint</th>
                <th>Protocol</th>
                <th>STARTTLS State</th>
                <th>Negotiated TLS</th>
                <th>Cipher Suite</th>
                <th>Risk Score</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((s) => (
                <tr key={s.id}>
                  <td className="mono">#{s.session_index}</td>
                  <td className="mono" style={{ fontSize: '0.8rem' }}>
                    {s.client_ip}:{s.client_port}
                  </td>
                  <td className="mono" style={{ fontSize: '0.8rem' }}>
                    {s.server_ip}:{s.server_port}
                    {s.hostname && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>{s.hostname}</div>
                    )}
                  </td>
                  <td>
                    <span
                      style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'var(--color-bg-secondary)',
                        fontWeight: 600,
                        fontSize: '0.75rem',
                      }}
                    >
                      {s.protocol}
                    </span>
                  </td>
                  <td>
                    <StarttlsStateBadge state={s.starttls_state} />
                  </td>
                  <td>
                    {s.tls_handshake?.negotiated_tls_version ? (
                      <span className="mono" style={{ color: 'var(--color-accent-cyan)' }}>
                        {s.tls_handshake.negotiated_tls_version}
                      </span>
                    ) : s.is_tls_implicit ? (
                      <span style={{ color: 'var(--color-accent-indigo)', fontSize: '0.8rem' }}>Implicit TLS</span>
                    ) : (
                      <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.8rem' }}>Plaintext</span>
                    )}
                  </td>
                  <td className="hash" style={{ maxWidth: '180px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                    {s.tls_handshake?.negotiated_cipher_suite || 'None'}
                  </td>
                  <td className="mono" style={{ fontWeight: 600 }}>
                    <span
                      style={{
                        color:
                          (s.risk_score || 0) >= 40
                            ? 'var(--color-high)'
                            : (s.risk_score || 0) >= 20
                            ? 'var(--color-warning)'
                            : 'var(--color-success)',
                      }}
                    >
                      {s.risk_score !== null && s.risk_score !== undefined ? s.risk_score.toFixed(1) : 'N/A'}
                    </span>
                  </td>
                  <td>
                    <button
                      onClick={() => navigate(`/sessions/${s.id}`)}
                      className="btn btn--ghost"
                      style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                    >
                      <Eye size={14} /> Inspect
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
      )}
    </div>
  );
};
