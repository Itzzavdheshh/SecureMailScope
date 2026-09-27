import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { Activity, Filter, RefreshCw, Layers } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { evidenceApi, type EvidenceFilterParams } from '../api/services';
import type { EvidenceRead, PaginatedResponse } from '../types/api';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const EvidencePage: React.FC = () => {
  const { activeCapture } = useWorkspace();
  const [searchParams] = useSearchParams();
  const [data, setData] = useState<PaginatedResponse<EvidenceRead> | null>(null);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<EvidenceFilterParams>({
    finding_id: searchParams.get('finding_id') || undefined,
    session_id: searchParams.get('session_id') || undefined,
    protocol_layer: searchParams.get('protocol_layer') || undefined,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchEvidence = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await evidenceApi.list({
        capture_id: activeCapture?.id,
        page: currentPage,
        page_size: 20,
        ...currentFilters,
      });
      setData(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch forensic packet evidence.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEvidence(page, filters);
  }, [page, activeCapture]);

  const handleFilterChange = (key: keyof EvidenceFilterParams, value: any) => {
    const nextFilters = { ...filters, [key]: value || undefined };
    setFilters(nextFilters);
    setPage(1);
    fetchEvidence(1, nextFilters);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Forensic Evidence Explorer</h2>
          <p>
            Trace exact packet field observations to security findings: FINDING &rarr; EVIDENCE &rarr; FRAME &rarr; PROTOCOL FIELD.
          </p>
        </div>
        <button onClick={() => fetchEvidence(page, filters)} className="btn btn--ghost">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ padding: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', fontSize: '0.85rem', fontWeight: 600 }}>
          <Filter size={16} style={{ color: 'var(--color-accent)' }} /> Evidence Filters
        </div>

        <div className="grid-content" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Protocol Layer
            </label>
            <select
              className="input"
              value={filters.protocol_layer || ''}
              onChange={(e) => handleFilterChange('protocol_layer', e.target.value)}
            >
              <option value="">All Layers</option>
              <option value="TCP">TCP Layer</option>
              <option value="TLS">TLS Handshake</option>
              <option value="SMTP">SMTP Protocol</option>
              <option value="IMAP">IMAP Protocol</option>
              <option value="POP3">POP3 Protocol</option>
              <option value="X509">X.509 Certificate</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', display: 'block', marginBottom: '4px' }}>
              Field Name
            </label>
            <input
              type="text"
              placeholder="e.g. negotiated_version"
              className="input"
              value={filters.field_name || ''}
              onChange={(e) => handleFilterChange('field_name', e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Evidence Items List */}
      {isLoading ? (
        <LoadingState message="Tracing packet evidence items..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchEvidence(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Evidence Items Found"
          subtitle="No forensic packet evidence matched the selected filter criteria."
          icon={<Activity size={40} />}
        />
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Frame</th>
                <th>Timestamp</th>
                <th>Layer</th>
                <th>Protocol Field</th>
                <th>Observed Value</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ fontWeight: 700, color: 'var(--color-accent)' }}>
                    #{ev.frame_number}
                  </td>
                  <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                    {ev.packet_timestamp ? ev.packet_timestamp.substring(11, 23) : 'N/A'}
                  </td>
                  <td>
                    <span
                      style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'var(--color-bg-primary)',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                      }}
                    >
                      {ev.protocol_layer}
                    </span>
                  </td>
                  <td className="mono" style={{ fontWeight: 600 }}>
                    {ev.field_name}
                  </td>
                  <td className="mono" style={{ color: 'var(--color-text)', maxWidth: '280px', wordBreak: 'break-all' }}>
                    "{ev.observed_value}"
                  </td>
                  <td>
                    {ev.session_id ? (
                      <Link
                        to={`/sessions/${ev.session_id}`}
                        className="btn btn--ghost"
                        style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                      >
                        <Layers size={14} /> Session
                      </Link>
                    ) : (
                      <span style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>-</span>
                    )}
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
