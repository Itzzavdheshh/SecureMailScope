import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FolderCheck, Play } from 'lucide-react';
import { useWorkspace, type EnrichedCapture } from '../context/WorkspaceContext';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { DataTable, type Column } from '../components/common/DataTable';
import { Pagination } from '../components/common/Pagination';
import { LoadingState, EmptyState } from '../components/common/StateViews';

export const CaptureRegistryPage: React.FC = () => {
  const { capturesList, activeCapture, isLoadingCaptures, selectCaptureById } = useWorkspace();
  const [searchVal, setSearchVal] = useState('');
  const [bandFilter, setBandFilter] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const navigate = useNavigate();

  const getRiskBadgeClass = (band?: string | null) => {
    if (!band) return 'badge--info';
    switch (band.toUpperCase()) {
      case 'HIGH':
      case 'CRITICAL':
        return 'badge--high';
      case 'MEDIUM':
        return 'badge--warning';
      case 'LOW':
      case 'SECURE':
        return 'badge--secure';
      default:
        return 'badge--info';
    }
  };

  const filterOptions: FilterOption[] = [
    {
      key: 'bandFilter',
      label: 'RISK BAND',
      options: [
        { label: 'HIGH / CRITICAL', value: 'HIGH' },
        { label: 'MEDIUM', value: 'MEDIUM' },
        { label: 'LOW / SECURE', value: 'SECURE' },
      ],
      value: bandFilter,
      onChange: (val) => {
        setBandFilter(val);
        setPage(1);
      },
    },
  ];

  const filteredCaptures = capturesList.filter((cap) => {
    if (bandFilter) {
      if (!cap.risk_band || !cap.risk_band.toUpperCase().includes(bandFilter.toUpperCase())) return false;
    }
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      cap.filename.toLowerCase().includes(term) ||
      cap.id.toLowerCase().includes(term) ||
      cap.sha256_hash.toLowerCase().includes(term)
    );
  });

  const totalPages = Math.ceil(filteredCaptures.length / pageSize) || 1;
  const paginatedCaptures = filteredCaptures.slice((page - 1) * pageSize, page * pageSize);

  const columns: Column<EnrichedCapture>[] = [
    {
      key: 'filename',
      header: 'CAPTURE FILENAME',
      render: (cap) => (
        <div>
          <div className="mono" style={{ fontWeight: 700, color: 'var(--color-blue-700)', fontSize: '13px' }}>
            {cap.filename}
            {cap.id === activeCapture?.id && (
              <span className="badge badge--info" style={{ marginLeft: '8px', fontSize: '9px', padding: '1px 5px' }}>
                ACTIVE
              </span>
            )}
          </div>
          <div className="hash" style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
            SHA-256: {cap.sha256_hash.substring(0, 16)}...
          </div>
        </div>
      ),
    },
    {
      key: 'packets',
      header: 'PACKETS / SIZE',
      width: '130px',
      render: (cap) => (
        <div style={{ fontSize: '12px' }}>
          <div className="mono" style={{ fontWeight: 600 }}>{cap.total_packets || 0} pkts</div>
          <div style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
            {(cap.file_size_bytes / 1024).toFixed(1)} KB
          </div>
        </div>
      ),
    },
    {
      key: 'sessions',
      header: 'SESSIONS',
      width: '90px',
      align: 'center',
      render: (cap) => <span className="mono" style={{ fontWeight: 600 }}>{cap.total_sessions || 0}</span>,
    },
    {
      key: 'findings',
      header: 'FINDINGS',
      width: '90px',
      align: 'center',
      render: (cap) => <span className="mono" style={{ fontWeight: 600 }}>{cap.total_findings || 0}</span>,
    },
    {
      key: 'risk',
      header: 'RISK SCORE',
      width: '120px',
      align: 'right',
      render: (cap) => (
        cap.risk_band ? (
          <span className={`badge ${getRiskBadgeClass(cap.risk_band)}`}>
            {cap.risk_band} ({cap.overall_risk_score !== null && cap.overall_risk_score !== undefined ? cap.overall_risk_score.toFixed(1) : 'N/A'})
          </span>
        ) : (
          <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>UNEVALUATED</span>
        )
      ),
    },
    {
      key: 'actions',
      header: 'ACTION',
      width: '160px',
      align: 'right',
      render: (cap) => (
        <button
          type="button"
          className="btn btn--primary"
          style={{ padding: '3px 8px', fontSize: '11px', gap: '4px' }}
          onClick={(e) => {
            e.stopPropagation();
            selectCaptureById(cap.id);
            navigate('/');
          }}
        >
          <Play size={12} />
          <span>Open Workspace</span>
        </button>
      ),
    },
  ];

  return (
    <div className="workspace-page">
      {/* Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Search filename, SHA-256 hash, ID..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        filters={filterOptions}
        onReset={() => {
          setSearchVal('');
          setBandFilter('');
        }}
      />

      {/* Table & Content */}
      {isLoadingCaptures ? (
        <LoadingState message="Loading investigation capture registry..." />
      ) : filteredCaptures.length === 0 ? (
        <EmptyState
          title="No Captures Found"
          subtitle="No network capture files matching the selected search criteria exist in this investigation."
          icon={<FolderCheck size={36} />}
        />
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <DataTable
            columns={columns}
            data={paginatedCaptures}
            keyExtractor={(cap) => cap.id}
            selectedKey={activeCapture?.id}
            onRowClick={(cap) => {
              selectCaptureById(cap.id);
              navigate('/');
            }}
          />
          <div style={{ borderTop: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
            <Pagination
              page={page}
              totalPages={totalPages}
              totalItems={filteredCaptures.length}
              pageSize={pageSize}
              onPageChange={(p) => setPage(p)}
            />
          </div>
        </div>
      )}
    </div>
  );
};
