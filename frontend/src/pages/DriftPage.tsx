import React, { useState, useEffect } from 'react';
import { TrendingDown, RefreshCw } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { driftsApi } from '../api/services';
import type { DriftEventRead, PaginatedResponse } from '../types/api';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { InspectorPanel } from '../components/common/InspectorPanel';
import { ComparisonPanel } from '../components/common/ComparisonPanel';

export const DriftPage: React.FC = () => {
  const { activeCapture, activeJob } = useWorkspace();
  const [data, setData] = useState<PaginatedResponse<DriftEventRead> | null>(null);
  const [page, setPage] = useState(1);
  const [selectedDrift, setSelectedDrift] = useState<DriftEventRead | null>(null);
  const [searchVal, setSearchVal] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchDrifts = async (currentPage = page) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await driftsApi.list({
        job_id: activeJob?.id,
        capture_id: activeCapture?.id,
        page: currentPage,
        page_size: 25,
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
    fetchDrifts(page);
  }, [page, activeJob, activeCapture]);

  const parseStateObj = (jsonStr?: string | null): Record<string, any> => {
    if (!jsonStr) return {};
    try {
      const parsed = JSON.parse(jsonStr);
      return typeof parsed === 'object' && parsed !== null ? parsed : { raw: jsonStr };
    } catch {
      return { raw: jsonStr };
    }
  };

  const columns: Column<DriftEventRead>[] = [
    {
      key: 'event_type',
      header: 'EVENT TYPE',
      width: '160px',
      render: (d) => (
        <span style={{ fontWeight: 700, color: 'var(--color-warning)', fontSize: '11px' }}>
          {d.event_type}
        </span>
      ),
    },
    {
      key: 'delta_description',
      header: 'DELTA DESCRIPTION',
      render: (d) => <span>{d.delta_description}</span>,
    },
    {
      key: 'risk_delta',
      header: 'RISK Δ',
      width: '60px',
      align: 'right',
      render: (d) => (
        <span className="mono" style={{ color: 'var(--color-high)', fontWeight: 700 }}>
          +{d.risk_delta ?? 0}
        </span>
      ),
    },
  ];

  const filteredItems = (data?.items || []).filter((d) => {
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      d.event_type.toLowerCase().includes(term) ||
      d.delta_description.toLowerCase().includes(term)
    );
  });

  return (
    <div className="workspace-page">
      {/* Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Filter event type, description..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        onReset={() => setSearchVal('')}
        actionButton={
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px 8px', fontSize: '12px' }}
            onClick={() => fetchDrifts(page)}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      {/* Main Master/Detail Layout */}
      {isLoading ? (
        <LoadingState message="Calculating baseline profile state deltas..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={() => fetchDrifts(page)} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Cryptographic Drift Observed"
          subtitle="No behavioral or security baseline drift events were detected for this analysis context."
          icon={<TrendingDown size={36} />}
        />
      ) : (
        <div className="master-detail-container">
          {/* Master Table */}
          <div className="master-pane">
            <DataTable
              columns={columns}
              data={filteredItems}
              keyExtractor={(d) => d.id}
              selectedKey={selectedDrift?.id}
              onRowClick={(d) => setSelectedDrift(d)}
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

          {/* Right Inspector Panel with Side-by-Side Comparison */}
          {selectedDrift && (
            <InspectorPanel
              title={`DRIFT: ${selectedDrift.event_type}`}
              subtitle={`Risk Delta: +${selectedDrift.risk_delta || 0} pts · Detected: ${new Date(selectedDrift.detected_at).toLocaleTimeString()}`}
              onClose={() => setSelectedDrift(null)}
            >
              <div className="inspector-section">
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text)' }}>
                  {selectedDrift.delta_description}
                </div>
              </div>

              <div className="inspector-section">
                <ComparisonPanel
                  title="SIDE-BY-SIDE PROFILE DELTA"
                  baseline={parseStateObj(selectedDrift.previous_state_json)}
                  current={parseStateObj(selectedDrift.new_state_json)}
                />
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">INFRASTRUCTURE ASSOCIATION</div>
                <div className="detail-row">
                  <div className="detail-row__label">Identity Key</div>
                  <div className="detail-row__value hash">{selectedDrift.infrastructure_id}</div>
                </div>
              </div>
            </InspectorPanel>
          )}
        </div>
      )}
    </div>
  );
};
