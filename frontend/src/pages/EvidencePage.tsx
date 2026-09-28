import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Activity, RefreshCw, ExternalLink } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { evidenceApi, type EvidenceFilterParams } from '../api/services';
import type { EvidenceRead, PaginatedResponse } from '../types/api';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { InspectorPanel } from '../components/common/InspectorPanel';

/**
 * Safely format packet timestamp values (which may be numeric Unix epoch,
 * ISO date strings, or null/undefined) for human-readable forensic display.
 */
export const formatPacketTimestamp = (
  val: number | string | null | undefined,
  short = false
): string => {
  if (val === null || val === undefined || val === '') return 'N/A';

  try {
    let date: Date;
    let subseconds = '';

    if (typeof val === 'number') {
      const isSeconds = val < 1e11;
      date = new Date(isSeconds ? val * 1000 : val);
      const strVal = String(val);
      if (strVal.includes('.')) {
        subseconds = '.' + strVal.split('.')[1].slice(0, 6);
      }
    } else {
      const strVal = String(val).trim();
      const numVal = Number(strVal);
      if (!isNaN(numVal) && strVal !== '') {
        const isSeconds = numVal < 1e11;
        date = new Date(isSeconds ? numVal * 1000 : numVal);
        if (strVal.includes('.')) {
          subseconds = '.' + strVal.split('.')[1].slice(0, 6);
        }
      } else {
        date = new Date(strVal);
      }
    }

    if (isNaN(date.getTime())) {
      return String(val);
    }

    const iso = date.toISOString();
    if (short) {
      const timePart = iso.substring(11, 19);
      const frac = subseconds || iso.substring(19, 23);
      return `${timePart}${frac}`;
    }

    const datePart = iso.substring(0, 10);
    const timePart = iso.substring(11, 19);
    const frac = subseconds || iso.substring(19, 23);
    return `${datePart} ${timePart}${frac} UTC`;
  } catch {
    return String(val);
  }
};

export const EvidencePage: React.FC = () => {
  const { activeCapture } = useWorkspace();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [data, setData] = useState<PaginatedResponse<EvidenceRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRead | null>(null);
  const [filters, setFilters] = useState<EvidenceFilterParams>({
    finding_id: searchParams.get('finding_id') || undefined,
    session_id: searchParams.get('session_id') || undefined,
    protocol_layer: searchParams.get('protocol_layer') || undefined,
  });
  const [searchVal, setSearchVal] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchEvidence = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await evidenceApi.list({
        capture_id: activeCapture?.id,
        page: currentPage,
        page_size: 25,
        ...currentFilters,
      });
      setData(res);
      if (res.items.length > 0 && !selectedEvidence) {
        setSelectedEvidence(res.items[0]);
      }
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

  const filterOptions: FilterOption[] = [
    {
      key: 'protocol_layer',
      label: 'Layer',
      value: filters.protocol_layer || '',
      options: [
        { label: 'TCP Layer', value: 'TCP' },
        { label: 'TLS Handshake', value: 'TLS' },
        { label: 'SMTP Protocol', value: 'SMTP' },
        { label: 'IMAP Protocol', value: 'IMAP' },
        { label: 'POP3 Protocol', value: 'POP3' },
        { label: 'X.509 Certificate', value: 'X509' },
      ],
      onChange: (val) => handleFilterChange('protocol_layer', val),
    },
  ];

  const columns: Column<EvidenceRead>[] = [
    {
      key: 'frame_number',
      header: 'FRAME',
      width: '65px',
      render: (ev) => (
        <span className="mono" style={{ fontWeight: 700, color: 'var(--color-blue-700)' }}>
          #{ev.frame_number}
        </span>
      ),
    },
    {
      key: 'protocol_layer',
      header: 'LAYER',
      width: '70px',
      render: (ev) => <span className="mono" style={{ fontSize: '11px' }}>{ev.protocol_layer}</span>,
    },
    {
      key: 'field_name',
      header: 'FIELD NAME',
      render: (ev) => <span style={{ fontWeight: 600 }}>{ev.field_name}</span>,
    },
  ];

  const filteredItems = (data?.items || []).filter((ev) => {
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      ev.field_name.toLowerCase().includes(term) ||
      ev.observed_value.toLowerCase().includes(term) ||
      String(ev.frame_number).includes(term) ||
      ev.protocol_layer.toLowerCase().includes(term)
    );
  });

  return (
    <div className="workspace-page">
      {/* Top Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Filter frame, layer, field, value..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        filters={filterOptions}
        onReset={() => {
          setFilters({});
          setSearchVal('');
          fetchEvidence(1, {});
        }}
        actionButton={
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px 8px', fontSize: '12px' }}
            onClick={() => fetchEvidence(page, filters)}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      {/* Main 3-Pane Workbench Layout */}
      {isLoading ? (
        <LoadingState message="Tracing forensic packet evidence lineage..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchEvidence(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Evidence Items Found"
          subtitle="No forensic packet evidence matched the selected filter criteria."
          icon={<Activity size={36} />}
        />
      ) : (
        <div className="master-detail-container">
          {/* Pane 1: Evidence Item List (30%) */}
          <div className="master-pane" style={{ flex: '0 0 320px' }}>
            <DataTable
              columns={columns}
              data={filteredItems}
              keyExtractor={(ev) => ev.id}
              selectedKey={selectedEvidence?.id}
              onRowClick={(ev) => setSelectedEvidence(ev)}
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

          {/* Pane 2: Evidence Record Detail (Flex 1) */}
          {selectedEvidence ? (
            <div className="master-pane" style={{ flex: 1, padding: '16px', gap: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--color-border)', paddingBottom: '10px' }}>
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>
                    EVIDENCE RECORD DETAILS
                  </div>
                  <div style={{ fontSize: '15px', fontWeight: 700, marginTop: '2px' }}>
                    Frame #{selectedEvidence.frame_number} · {selectedEvidence.protocol_layer}
                  </div>
                </div>

                <div className="badge badge--info" style={{ fontSize: '11px' }}>
                  {selectedEvidence.protocol_layer} LAYER
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-row__label">Field Identifier</div>
                <div className="detail-row__value mono" style={{ fontWeight: 700 }}>
                  {selectedEvidence.field_name}
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-row__label">Observed Value</div>
                <div className="detail-row__value mono" style={{ color: 'var(--color-blue-700)', wordBreak: 'break-all' }}>
                  "{selectedEvidence.observed_value}"
                </div>
              </div>

              <div className="detail-row">
                <div className="detail-row__label">Packet Timestamp</div>
                <div className="detail-row__value mono">
                  {formatPacketTimestamp(selectedEvidence.packet_timestamp)}
                </div>
              </div>

              {(selectedEvidence.raw_hex_snippet || selectedEvidence.hex_dump_snippet) && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                    HEX PAYLOAD SNIPPET
                  </div>
                  <pre style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', padding: '10px', background: 'var(--color-surface-inset)', borderRadius: 'var(--radius-sm)' }}>
                    {selectedEvidence.raw_hex_snippet || selectedEvidence.hex_dump_snippet}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="master-pane" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-muted)' }}>
              Select an evidence item from the left pane to view details.
            </div>
          )}

          {/* Pane 3: Linked Packet Frame Inspector (320px) */}
          {selectedEvidence && (
            <InspectorPanel
              title={`FRAME #${selectedEvidence.frame_number}`}
              subtitle={`Packet Timestamp: ${formatPacketTimestamp(selectedEvidence.packet_timestamp, true)}`}
              onClose={() => setSelectedEvidence(null)}
            >

              <div className="inspector-section">
                <div className="inspector-section-title">FRAME METADATA</div>
                <div className="detail-row">
                  <div className="detail-row__label">Frame Number</div>
                  <div className="detail-row__value mono" style={{ fontWeight: 700 }}>
                    #{selectedEvidence.frame_number}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Protocol Layer</div>
                  <div className="detail-row__value mono">
                    {selectedEvidence.protocol_layer}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Finding ID</div>
                  <div className="detail-row__value mono">
                    {selectedEvidence.finding_id ? `FND-${selectedEvidence.finding_id.substring(0, 8)}` : 'None direct'}
                  </div>
                </div>
              </div>

              <div style={{ marginTop: 'auto', paddingTop: '12px' }}>
                {selectedEvidence.session_id ? (
                  <button
                    type="button"
                    className="btn btn--primary"
                    style={{ width: '100%', justifyContent: 'center', fontSize: '12px', gap: '6px' }}
                    onClick={() => navigate(`/sessions/${selectedEvidence.session_id}`)}
                  >
                    <ExternalLink size={14} />
                    <span>Open Parent Mail Session</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn btn--secondary"
                    style={{ width: '100%', justifyContent: 'center', fontSize: '12px', opacity: 0.6 }}
                    disabled
                  >
                    No Session Link
                  </button>
                )}
              </div>
            </InspectorPanel>
          )}
        </div>
      )}
    </div>
  );
};
