import React, { useState, useEffect } from 'react';
import { Server, RefreshCw } from 'lucide-react';
import { infrastructureApi } from '../api/services';
import type { InfrastructureIdentityRead, PaginatedResponse } from '../types/api';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { InspectorPanel } from '../components/common/InspectorPanel';

export const InfrastructurePage: React.FC = () => {
  const [data, setData] = useState<PaginatedResponse<InfrastructureIdentityRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedIdentity, setSelectedIdentity] = useState<InfrastructureIdentityRead | null>(null);
  const [searchVal, setSearchVal] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchInfra = async (currentPage = page) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await infrastructureApi.list(currentPage, 25);
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

  const filterOptions: FilterOption[] = [
    {
      key: 'protocol',
      label: 'Protocol',
      value: protocolFilter,
      options: [
        { label: 'SMTP', value: 'SMTP' },
        { label: 'IMAP', value: 'IMAP' },
        { label: 'POP3', value: 'POP3' },
      ],
      onChange: (val) => setProtocolFilter(val),
    },
  ];

  const columns: Column<InfrastructureIdentityRead>[] = [
    {
      key: 'endpoint',
      header: 'SERVER ENDPOINT',
      render: (inf) => (
        <span className="mono" style={{ fontWeight: 700, color: 'var(--color-blue-700)' }}>
          {inf.ip_address}:{inf.port}
        </span>
      ),
    },
    {
      key: 'protocol',
      header: 'PROTO',
      width: '65px',
      render: (inf) => <span className="mono">{inf.protocol}</span>,
    },
    {
      key: 'hostname',
      header: 'HOSTNAME',
      render: (inf) => <span>{inf.hostname || '-'}</span>,
    },
    {
      key: 'drifts',
      header: 'DRIFTS',
      width: '60px',
      align: 'right',
      render: (inf) => (
        <span className="mono" style={{ color: (inf.drift_events?.length || 0) > 0 ? 'var(--color-warning)' : 'inherit' }}>
          {inf.drift_events?.length || 0}
        </span>
      ),
    },
    {
      key: 'risk',
      header: 'RISK',
      width: '60px',
      align: 'right',
      render: (inf) => (
        <span
          className="mono"
          style={{
            fontWeight: 700,
            color:
              (inf.current_risk_score || 0) >= 40
                ? 'var(--color-high)'
                : (inf.current_risk_score || 0) >= 20
                ? 'var(--color-warning)'
                : 'var(--color-success)',
          }}
        >
          {inf.current_risk_score !== null && inf.current_risk_score !== undefined
            ? inf.current_risk_score.toFixed(1)
            : '-'}
        </span>
      ),
    },
  ];

  const filteredItems = (data?.items || []).filter((inf) => {
    if (protocolFilter && inf.protocol !== protocolFilter) return false;
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      inf.ip_address.toLowerCase().includes(term) ||
      (inf.hostname && inf.hostname.toLowerCase().includes(term)) ||
      inf.identity_key.toLowerCase().includes(term)
    );
  });

  return (
    <div className="workspace-page">
      {/* Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Filter IP, hostname, key..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        filters={filterOptions}
        onReset={() => {
          setSearchVal('');
          setProtocolFilter('');
        }}
        actionButton={
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px 8px', fontSize: '12px' }}
            onClick={() => fetchInfra(page)}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      {/* Main Master/Detail Layout */}
      {isLoading ? (
        <LoadingState message="Resolving infrastructure identity baselines..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchInfra(page)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Infrastructure Identities"
          subtitle="No server identities have been evaluated yet in the database."
          icon={<Server size={36} />}
        />
      ) : (
        <div className="master-detail-container">
          {/* Master Table */}
          <div className="master-pane">
            <DataTable
              columns={columns}
              data={filteredItems}
              keyExtractor={(inf) => inf.id}
              selectedKey={selectedIdentity?.id}
              onRowClick={(inf) => setSelectedIdentity(inf)}
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
          {selectedIdentity && (
            <InspectorPanel
              title={`IDENTITY: ${selectedIdentity.ip_address}:${selectedIdentity.port}`}
              subtitle={`${selectedIdentity.protocol} · Hostname: ${selectedIdentity.hostname || 'None'}`}
              onClose={() => setSelectedIdentity(null)}
            >
              <div className="inspector-section">
                <div className="inspector-section-title">IDENTITY METADATA</div>
                <div className="detail-row">
                  <div className="detail-row__label">Identity Key</div>
                  <div className="detail-row__value hash">{selectedIdentity.identity_key}</div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">First Seen</div>
                  <div className="detail-row__value mono" style={{ fontSize: '11px' }}>
                    {new Date(selectedIdentity.first_seen_at).toLocaleString()}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Last Seen</div>
                  <div className="detail-row__value mono" style={{ fontSize: '11px' }}>
                    {new Date(selectedIdentity.last_seen_at).toLocaleString()}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Current Risk</div>
                  <div className="detail-row__value mono" style={{ fontWeight: 700 }}>
                    {selectedIdentity.current_risk_score !== null && selectedIdentity.current_risk_score !== undefined
                      ? selectedIdentity.current_risk_score.toFixed(1)
                      : '0.0'}
                  </div>
                </div>
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">CRYPTOGRAPHIC BASELINE PROFILE</div>
                <pre
                  style={{
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    padding: '8px',
                    background: 'var(--color-surface-inset)',
                    borderRadius: 'var(--radius-sm)',
                    maxHeight: '160px',
                    overflowY: 'auto',
                  }}
                >
                  {selectedIdentity.active_profile_json
                    ? JSON.stringify(JSON.parse(selectedIdentity.active_profile_json), null, 2)
                    : 'No active profile JSON recorded'}
                </pre>
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">
                  DRIFT HISTORY ({selectedIdentity.drift_events?.length || 0})
                </div>
                {(!selectedIdentity.drift_events || selectedIdentity.drift_events.length === 0) ? (
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    No baseline drift events observed for this identity.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {selectedIdentity.drift_events.map((d) => (
                      <div
                        key={d.id}
                        style={{
                          padding: '6px 8px',
                          background: 'var(--color-warning-bg)',
                          borderLeft: '3px solid var(--color-warning)',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '11px',
                        }}
                      >
                        <div style={{ fontWeight: 700, color: 'var(--color-warning)' }}>{d.event_type}</div>
                        <div style={{ color: 'var(--color-text-secondary)', marginTop: '2px' }}>{d.delta_description}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </InspectorPanel>
          )}
        </div>
      )}
    </div>
  );
};
