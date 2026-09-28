import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ShieldAlert, Activity, RefreshCw, ExternalLink } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { findingsApi, type FindingFilterParams } from '../api/services';
import type { FindingRead, PaginatedResponse } from '../types/api';
import { SeverityBadge } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { InspectorPanel } from '../components/common/InspectorPanel';

export const FindingsPage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const [searchParams] = useSearchParams();
  const [data, setData] = useState<PaginatedResponse<FindingRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedFinding, setSelectedFinding] = useState<FindingRead | null>(null);
  const [filters, setFilters] = useState<FindingFilterParams>({
    severity: searchParams.get('severity') || undefined,
  });
  const [searchVal, setSearchVal] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchFindings = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await findingsApi.list({
        job_id: activeJob?.id,
        page: currentPage,
        page_size: 25,
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

  const filterOptions: FilterOption[] = [
    {
      key: 'severity',
      label: 'Severity',
      value: filters.severity || '',
      options: [
        { label: 'CRITICAL', value: 'CRITICAL' },
        { label: 'HIGH', value: 'HIGH' },
        { label: 'MEDIUM', value: 'MEDIUM' },
        { label: 'LOW', value: 'LOW' },
        { label: 'INFO', value: 'INFO' },
      ],
      onChange: (val) => handleFilterChange('severity', val),
    },
    {
      key: 'category',
      label: 'Category',
      value: filters.category || '',
      options: [
        { label: 'TLS & Cipher Suites', value: 'TLS_CRYPTO' },
        { label: 'X.509 Certificates', value: 'X509_CERT' },
        { label: 'STARTTLS Negotiation', value: 'STARTTLS' },
        { label: 'Protocol Anomalies', value: 'PROTOCOL_ANOMALY' },
      ],
      onChange: (val) => handleFilterChange('category', val),
    },
  ];

  const columns: Column<FindingRead>[] = [
    {
      key: 'rule_id',
      header: 'RULE ID',
      width: '90px',
      render: (f) => <span className="mono" style={{ fontWeight: 700 }}>{f.rule_id}</span>,
    },
    {
      key: 'severity',
      header: 'SEV',
      width: '80px',
      render: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      key: 'title',
      header: 'FINDING TITLE',
      render: (f) => <span style={{ fontWeight: 600 }}>{f.title}</span>,
    },
    {
      key: 'evidence_count',
      header: 'EVIDENCE',
      width: '70px',
      align: 'right',
      render: (f) => (
        <span className="mono" style={{ fontSize: '11px', color: 'var(--color-blue-700)' }}>
          {f.evidence?.length || 0} PKTS
        </span>
      ),
    },
    {
      key: 'score_contribution',
      header: 'SCORE',
      width: '60px',
      align: 'right',
      render: (f) => (
        <span className="mono" style={{ color: 'var(--color-high)', fontWeight: 700 }}>
          +{f.score_contribution}
        </span>
      ),
    },
  ];

  const filteredItems = (data?.items || []).filter((f) => {
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      f.rule_id.toLowerCase().includes(term) ||
      f.title.toLowerCase().includes(term) ||
      f.description.toLowerCase().includes(term) ||
      f.category.toLowerCase().includes(term)
    );
  });

  return (
    <div className="workspace-page">
      {/* Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Search Rule ID, title, text..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        filters={filterOptions}
        onReset={() => {
          setFilters({});
          setSearchVal('');
          fetchFindings(1, {});
        }}
        actionButton={
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px 8px', fontSize: '12px' }}
            onClick={() => fetchFindings(page, filters)}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      {/* Main Master/Detail Layout */}
      {isLoading ? (
        <LoadingState message="Evaluating Phase 5 security rules against capture evidence..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchFindings(page, filters)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Security Findings Observed"
          subtitle="No rule violations were detected for the selected capture and search filters."
          icon={<ShieldAlert size={36} />}
        />
      ) : (
        <div className="master-detail-container">
          {/* Master Table */}
          <div className="master-pane">
            <DataTable
              columns={columns}
              data={filteredItems}
              keyExtractor={(f) => f.id}
              selectedKey={selectedFinding?.id}
              onRowClick={(f) => setSelectedFinding(f)}
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
          {selectedFinding && (
            <InspectorPanel
              title={`FINDING: ${selectedFinding.rule_id}`}
              subtitle={`${selectedFinding.category} · Score Impact: +${selectedFinding.score_contribution}`}
              onClose={() => setSelectedFinding(null)}
            >
              <div className="inspector-section">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <SeverityBadge severity={selectedFinding.severity} />
                  <span style={{ fontSize: '13px', fontWeight: 700 }}>{selectedFinding.title}</span>
                </div>
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">WHAT WAS OBSERVED</div>
                <div style={{ fontSize: '12px', lineHeight: 1.5, color: 'var(--color-text)' }}>
                  {selectedFinding.description}
                </div>
              </div>

              {selectedFinding.remediation_recommendation && (
                <div className="inspector-section">
                  <div className="inspector-section-title">REMEDIATION RECOMMENDATION</div>
                  <div
                    style={{
                      fontSize: '11px',
                      lineHeight: 1.4,
                      background: 'var(--color-blue-050)',
                      padding: '8px',
                      borderRadius: 'var(--radius-sm)',
                      borderLeft: '3px solid var(--color-blue-700)',
                      color: 'var(--color-blue-900)',
                    }}
                  >
                    {selectedFinding.remediation_recommendation}
                  </div>
                </div>
              )}

              <div className="inspector-section">
                <div className="inspector-section-title">ATTACHED PACKET EVIDENCE ({selectedFinding.evidence?.length || 0})</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {selectedFinding.evidence?.map((ev) => (
                    <div
                      key={ev.id}
                      style={{
                        padding: '6px 8px',
                        background: 'var(--color-bg-primary)',
                        border: '1px solid var(--color-border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                      }}
                    >
                      <div style={{ color: 'var(--color-blue-700)', fontWeight: 600 }}>
                        Frame #{ev.frame_number} [{ev.protocol_layer}]
                      </div>
                      <div style={{ color: 'var(--color-text-muted)', fontSize: '10px' }}>
                        {ev.field_name}: <span style={{ color: 'var(--color-text)' }}>"{ev.observed_value}"</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: 'auto', paddingTop: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <Link
                  to={`/evidence?finding_id=${selectedFinding.id}`}
                  className="btn btn--secondary"
                  style={{ justifyContent: 'center', fontSize: '12px', gap: '6px' }}
                >
                  <Activity size={14} />
                  <span>Explore Full Evidence Lineage</span>
                </Link>

                {selectedFinding.session_id && (
                  <Link
                    to={`/sessions/${selectedFinding.session_id}`}
                    className="btn btn--primary"
                    style={{ justifyContent: 'center', fontSize: '12px', gap: '6px' }}
                  >
                    <ExternalLink size={14} />
                    <span>Inspect Associated Mail Session</span>
                  </Link>
                )}
              </div>
            </InspectorPanel>
          )}
        </div>
      )}
    </div>
  );
};
