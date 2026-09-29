import React, { useState, useEffect } from 'react';
import { Server, Activity, Clock } from 'lucide-react';
import { infrastructureApi, sessionsApi } from '../api/services';
import type { InfrastructureIdentityRead, PaginatedResponse } from '../types/api';
import { useWorkspace } from '../context/WorkspaceContext';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { InspectorPanel } from '../components/common/InspectorPanel';

export const InfrastructurePage: React.FC = () => {
  const { activeCapture, activeJob } = useWorkspace();
  const [data, setData] = useState<PaginatedResponse<InfrastructureIdentityRead> | null>(null);
  const [currentCaptureIps, setCurrentCaptureIps] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const [searchVal, setSearchVal] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [selectedIdentity, setSelectedIdentity] = useState<InfrastructureIdentityRead | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchInfra = async (currentPage = page) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await infrastructureApi.list(currentPage, 50);
      setData(res);

      if (activeJob?.id) {
        try {
          const sessionsRes = await sessionsApi.list({ job_id: activeJob.id, page: 1, page_size: 100 });
          const ips = new Set(sessionsRes.items.map((s) => s.server_ip));
          setCurrentCaptureIps(ips);
        } catch {
          setCurrentCaptureIps(new Set());
        }
      } else {
        setCurrentCaptureIps(new Set());
      }

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
  }, [page, activeJob, activeCapture]);

  const filterOptions: FilterOption[] = [
    {
      key: 'protocolFilter',
      label: 'PROTOCOL',
      options: [
        { label: 'SMTP', value: 'SMTP' },
        { label: 'IMAP', value: 'IMAP' },
        { label: 'POP3', value: 'POP3' },
      ],
      value: protocolFilter,
      onChange: (val) => setProtocolFilter(val),
    },
  ];

  const columns: Column<InfrastructureIdentityRead>[] = [
    {
      key: 'ip_address',
      header: 'SERVER IP & PORT',
      render: (inf) => (
        <span className="mono" style={{ fontWeight: 700, color: 'var(--color-blue-700)' }}>
          {inf.ip_address}:{inf.port || 25}
        </span>
      ),
    },
    {
      key: 'protocol',
      header: 'PROTO',
      width: '65px',
      render: (inf) => <span className="mono">{inf.protocol || 'SMTP'}</span>,
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
      (inf.identity_key && inf.identity_key.toLowerCase().includes(term))
    );
  });

  const currentCaptureItems = filteredItems.filter(
    (inf) => currentCaptureIps.has(inf.ip_address) || inf.last_evaluated_job_id === activeJob?.id
  );

  const historicalItems = filteredItems.filter(
    (inf) => !currentCaptureIps.has(inf.ip_address) && inf.last_evaluated_job_id !== activeJob?.id
  );

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
      />

      {/* Main Content */}
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
          <div className="master-pane" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

            {/* SECTION 1: CURRENT CAPTURE OBSERVATIONS */}
            <div className="card" style={{ padding: 0 }}>
              <div className="card-header" style={{ padding: '10px 16px', borderBottom: '1px solid var(--color-border)', backgroundColor: 'rgba(59, 130, 246, 0.05)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Activity size={16} color="var(--color-blue-700)" />
                  <span className="card-title" style={{ fontSize: '12px' }}>
                    CURRENT CAPTURE OBSERVATIONS ({currentCaptureItems.length})
                  </span>
                </div>
                <span className="badge badge--info" style={{ fontSize: '10px' }}>
                  {activeCapture?.filename}
                </span>
              </div>

              {currentCaptureItems.length === 0 ? (
                <div style={{ padding: '16px', textTransform: 'uppercase', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', letterSpacing: '0.05em' }}>
                  NO INFRASTRUCTURE OBSERVED IN CURRENT CAPTURE
                </div>
              ) : (
                <DataTable
                  columns={columns}
                  data={currentCaptureItems}
                  keyExtractor={(inf) => inf.id}
                  selectedKey={selectedIdentity?.id}
                  onRowClick={(inf) => setSelectedIdentity(inf)}
                />
              )}
            </div>

            {/* SECTION 2: HISTORICAL OBSERVATIONS */}
            {historicalItems.length > 0 && (
              <div className="card" style={{ padding: 0 }}>
                <div className="card-header" style={{ padding: '10px 16px', borderBottom: '1px solid var(--color-border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Clock size={16} color="var(--color-text-muted)" />
                    <span className="card-title" style={{ fontSize: '12px' }}>
                      HISTORICAL / INVESTIGATION-WIDE OBSERVATIONS ({historicalItems.length})
                    </span>
                  </div>
                  <span className="badge badge--warning" style={{ fontSize: '10px' }}>
                    OTHER CAPTURES IN INVESTIGATION
                  </span>
                </div>

                <DataTable
                  columns={columns}
                  data={historicalItems}
                  keyExtractor={(inf) => inf.id}
                  selectedKey={selectedIdentity?.id}
                  onRowClick={(inf) => setSelectedIdentity(inf)}
                />
              </div>
            )}

            <div style={{ borderTop: '1px solid var(--color-border)', background: 'var(--color-surface)', padding: '4px' }}>
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
              title={`IDENTITY: ${selectedIdentity.ip_address}:${selectedIdentity.port || 25}`}
              subtitle={`${selectedIdentity.protocol || 'SMTP'} • Hostname: ${selectedIdentity.hostname || 'None'}`}
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
