import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layers, ExternalLink, RefreshCw } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { sessionsApi, type SessionFilterParams } from '../api/services';
import type { EmailSessionRead, PaginatedResponse } from '../types/api';
import { StarttlsStateBadge } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { InspectorPanel } from '../components/common/InspectorPanel';

export const SessionsPage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const [data, setData] = useState<PaginatedResponse<EmailSessionRead> | null>(null);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<SessionFilterParams>({});
  const [searchVal, setSearchVal] = useState('');
  const [selectedSession, setSelectedSession] = useState<EmailSessionRead | null>(null);
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
        page_size: 25,
        ...currentFilters,
      });
      setData(res);
      if (res.items.length > 0 && !selectedSession) {
        setSelectedSession(res.items[0]);
      }
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

  const filterOptions: FilterOption[] = [
    {
      key: 'protocol',
      label: 'Protocol',
      value: filters.protocol || '',
      options: [
        { label: 'SMTP', value: 'SMTP' },
        { label: 'IMAP', value: 'IMAP' },
        { label: 'POP3', value: 'POP3' },
      ],
      onChange: (val) => handleFilterChange('protocol', val),
    },
    {
      key: 'starttls_state',
      label: 'STARTTLS State',
      value: filters.starttls_state || '',
      options: [
        { label: 'NOT OBSERVED', value: 'NOT_OBSERVED' },
        { label: 'ADVERTISED', value: 'ADVERTISED' },
        { label: 'ATTEMPTED', value: 'ATTEMPTED' },
        { label: 'ESTABLISHED', value: 'ESTABLISHED' },
        { label: 'REJECTED', value: 'REJECTED' },
        { label: 'CLEARTEXT FALLBACK', value: 'CLEARTEXT_FALLBACK' },
      ],
      onChange: (val) => handleFilterChange('starttls_state', val),
    },
    {
      key: 'tls_version',
      label: 'TLS',
      value: filters.tls_version || '',
      options: [
        { label: 'TLS 1.3', value: 'TLS 1.3' },
        { label: 'TLS 1.2', value: 'TLS 1.2' },
        { label: 'TLS 1.1', value: 'TLS 1.1' },
        { label: 'TLS 1.0', value: 'TLS 1.0' },
      ],
      onChange: (val) => handleFilterChange('tls_version', val),
    },
  ];

  const columns: Column<EmailSessionRead>[] = [
    {
      key: 'session_index',
      header: 'INDEX',
      width: '60px',
      render: (s) => <span className="mono">#{s.session_index}</span>,
    },
    {
      key: 'client_endpoint',
      header: 'CLIENT ENDPOINT',
      render: (s) => (
        <span className="mono" style={{ fontSize: '11px' }}>
          {s.client_ip}:{s.client_port}
        </span>
      ),
    },
    {
      key: 'server_endpoint',
      header: 'SERVER ENDPOINT',
      render: (s) => (
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <span className="mono" style={{ fontSize: '11px' }}>
            {s.server_ip}:{s.server_port}
          </span>
          {s.hostname && <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>{s.hostname}</span>}
        </div>
      ),
    },
    {
      key: 'protocol',
      header: 'PROTO',
      width: '60px',
      render: (s) => <span className="mono" style={{ fontWeight: 600 }}>{s.protocol}</span>,
    },
    {
      key: 'starttls_state',
      header: 'STARTTLS STATE',
      render: (s) => <StarttlsStateBadge state={s.starttls_state} />,
    },
    {
      key: 'tls_version',
      header: 'NEGOTIATED TLS',
      render: (s) => (
        s.tls_handshake?.negotiated_tls_version ? (
          <span className="mono" style={{ color: 'var(--color-blue-700)', fontWeight: 600 }}>
            {s.tls_handshake.negotiated_tls_version}
          </span>
        ) : s.is_tls_implicit ? (
          <span style={{ color: 'var(--color-info)', fontSize: '11px' }}>Implicit TLS</span>
        ) : (
          <span style={{ color: 'var(--color-text-muted)', fontSize: '11px' }}>Plaintext</span>
        )
      ),
    },
    {
      key: 'risk_score',
      header: 'RISK',
      width: '60px',
      align: 'right',
      render: (s) => (
        <span
          className="mono"
          style={{
            fontWeight: 700,
            color:
              (s.risk_score || 0) >= 40
                ? 'var(--color-high)'
                : (s.risk_score || 0) >= 20
                ? 'var(--color-warning)'
                : 'var(--color-success)',
          }}
        >
          {s.risk_score !== null && s.risk_score !== undefined ? s.risk_score.toFixed(1) : '-'}
        </span>
      ),
    },
  ];

  const filteredItems = (data?.items || []).filter((s) => {
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      s.client_ip.toLowerCase().includes(term) ||
      s.server_ip.toLowerCase().includes(term) ||
      (s.hostname && s.hostname.toLowerCase().includes(term)) ||
      s.protocol.toLowerCase().includes(term)
    );
  });

  return (
    <div className="workspace-page">
      {/* Top Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Filter IP, hostname, protocol..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        filters={filterOptions}
        onReset={() => {
          setFilters({});
          setSearchVal('');
          fetchSessions(1, {});
        }}
        actionButton={
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px 8px', fontSize: '12px' }}
            onClick={() => fetchSessions(page, filters)}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      {/* Main Master/Detail Layout */}
      {isLoading ? (
        <LoadingState message="Reconstructing mail sessions and extracting handshake parameters..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchSessions(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Reconstructed Mail Sessions"
          subtitle="No email sessions matching the selected filter criteria were found."
          icon={<Layers size={36} />}
        />
      ) : (
        <div className="master-detail-container">
          {/* Master Table */}
          <div className="master-pane">
            <DataTable
              columns={columns}
              data={filteredItems}
              keyExtractor={(s) => s.id}
              selectedKey={selectedSession?.id}
              onRowClick={(s) => setSelectedSession(s)}
            />

            <div style={{ borderTop: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
              <Pagination
                page={data.page}
                totalPages={data.total_pages}
                totalItems={data.total}
                pageSize={data.page_size}
                onPageChange={(p) => setPage(p)}
              />
            </div>
          </div>

          {/* Right Inspector Panel */}
          {selectedSession && (
            <InspectorPanel
              title={`SESSION #${selectedSession.session_index}`}
              subtitle={`${selectedSession.protocol} · ${selectedSession.client_ip}:${selectedSession.client_port} → ${selectedSession.server_ip}:${selectedSession.server_port}`}
              onClose={() => setSelectedSession(null)}
            >
              <div className="inspector-section">
                <div className="inspector-section-title">SECURITY POSTURE & RISK</div>
                <div className="detail-row">
                  <div className="detail-row__label">Risk Score</div>
                  <div className="detail-row__value" style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {selectedSession.risk_score !== null && selectedSession.risk_score !== undefined
                      ? selectedSession.risk_score.toFixed(1)
                      : '0.0'}
                    <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}> / 100</span>
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">STARTTLS State</div>
                  <div className="detail-row__value">
                    <StarttlsStateBadge state={selectedSession.starttls_state} />
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Implicit TLS</div>
                  <div className="detail-row__value">
                    {selectedSession.is_tls_implicit ? 'Yes' : 'No'}
                  </div>
                </div>
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">CRYPTOGRAPHIC PARAMETERS</div>
                <div className="detail-row">
                  <div className="detail-row__label">TLS Version</div>
                  <div className="detail-row__value mono">
                    {selectedSession.tls_handshake?.negotiated_tls_version || 'None (Plaintext)'}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Cipher Suite</div>
                  <div className="detail-row__value hash">
                    {selectedSession.tls_handshake?.negotiated_cipher_suite || 'None'}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Certificate</div>
                  <div className="detail-row__value hash">
                    {selectedSession.certificates?.[0]?.sha256_fingerprint
                      || <span style={{ color: 'var(--color-text-muted)', fontStyle: 'italic', fontFamily: 'var(--font-body)' }}>Open full session detail to inspect certificate</span>}
                  </div>
                </div>
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">TRAFFIC METRICS & PACKETS</div>
                <div className="detail-row">
                  <div className="detail-row__label">Packet Count</div>
                  <div className="detail-row__value mono">
                    {selectedSession.packet_count} packets ({selectedSession.bytes_transferred.toLocaleString()} bytes)
                  </div>
                </div>
              </div>

              <div style={{ marginTop: 'auto', paddingTop: '12px' }}>
                <button
                  type="button"
                  className="btn btn--primary"
                  style={{ width: '100%', justifyContent: 'center', fontSize: '12px', gap: '6px' }}
                  onClick={() => navigate(`/sessions/${selectedSession.id}`)}
                >
                  <ExternalLink size={14} />
                  <span>Inspect Full Packet Stream & Transcript</span>
                </button>
              </div>
            </InspectorPanel>
          )}
        </div>
      )}
    </div>
  );
};
