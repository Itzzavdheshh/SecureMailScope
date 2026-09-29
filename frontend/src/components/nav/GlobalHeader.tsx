import React, { useState } from 'react';
import { Search, Download, ChevronDown, FileCode, FileText, FileSpreadsheet, Layers } from 'lucide-react';
import { useWorkspace } from '../../context/WorkspaceContext';
import { reportsApi } from '../../api/services';
import { CaptureSelectorModal } from './CaptureSelectorModal';

export const GlobalHeader: React.FC = () => {
  const { investigationName, activeCapture, activeJob } = useWorkspace();
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showCaptureModal, setShowCaptureModal] = useState(false);

  const handleReportAction = (format: 'json' | 'html' | 'pdf') => {
    if (!activeJob) return;
    const url = reportsApi.getJobReportUrl(activeJob.id, format);
    if (format === 'json' || format === 'html') {
      window.open(url, '_blank');
    } else {
      window.location.href = url;
    }
    setShowExportMenu(false);
  };

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

  return (
    <header className="global-header">
      {/* Left section: Product title & active investigation bar */}
      <div className="global-header-left" style={{ gap: '12px', minWidth: 0, flex: 1 }}>
        <span className="global-header-title" style={{ flexShrink: 0 }}>SECUREMAILSCOPE</span>
        <span style={{ color: 'var(--color-border)', fontSize: '14px', flexShrink: 0 }}>|</span>

        <div className="investigation-bar" style={{ minWidth: 0, flexShrink: 1 }}>
          <span className="investigation-bar-label" style={{ flexShrink: 0 }}>INVESTIGATION:</span>
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '180px' }} title={investigationName}>
            {investigationName}
          </span>

          <span style={{ color: 'var(--color-border)', fontSize: '12px', flexShrink: 0 }}>•</span>

          <span className="investigation-bar-label" style={{ flexShrink: 0 }}>CAPTURE:</span>
          {activeCapture ? (
            <>
              <span className="investigation-bar-file" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '200px' }} title={activeCapture.filename}>
                {activeCapture.filename}
              </span>
              <span className="badge badge--info" style={{ fontSize: '10px', padding: '1px 5px', flexShrink: 0 }}>
                {activeCapture.total_packets ? `${activeCapture.total_packets} PKTS` : 'READY'}
              </span>
              {activeCapture.risk_band && (
                <span className={`badge ${getRiskBadgeClass(activeCapture.risk_band)}`} style={{ fontSize: '10px', padding: '1px 5px', flexShrink: 0 }}>
                  {activeCapture.risk_band}
                </span>
              )}
            </>
          ) : (
            <span style={{ color: 'var(--color-text-muted)', fontStyle: 'italic' }}>No capture loaded</span>
          )}

          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '2px 8px', fontSize: '11px', gap: '4px', flexShrink: 0, border: '1px solid var(--color-border)', marginLeft: '4px' }}
            onClick={() => setShowCaptureModal(true)}
          >
            <Layers size={12} color="var(--color-blue-700)" />
            <span>Change Capture</span>
            <ChevronDown size={12} />
          </button>
        </div>
      </div>

      {/* Right section: Search input & Report dropdown */}
      <div className="global-header-right" style={{ flexShrink: 0 }}>
        <div className="command-search-input">
          <Search size={14} />
          <input type="text" placeholder="Search sessions, rules, IPs... (Ctrl+K)" />
        </div>

        <div style={{ position: 'relative' }}>
          <button
            type="button"
            className="btn btn--primary"
            style={{ padding: '4px 10px', fontSize: '12px', gap: '6px' }}
            onClick={() => setShowExportMenu(!showExportMenu)}
            disabled={!activeJob}
          >
            <Download size={14} />
            <span>Export Report</span>
            <ChevronDown size={12} />
          </button>

          {showExportMenu && activeJob && (
            <div
              style={{
                position: 'absolute',
                top: '100%',
                right: 0,
                marginTop: '4px',
                background: 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-md)',
                boxShadow: 'var(--shadow-md)',
                zIndex: 150,
                minWidth: '180px',
                padding: '4px',
              }}
            >
              <button
                type="button"
                className="btn btn--ghost"
                style={{ width: '100%', justifyContent: 'flex-start', fontSize: '12px', padding: '6px 10px' }}
                onClick={() => handleReportAction('json')}
              >
                <FileCode size={14} color="var(--color-blue-600)" />
                <span>Raw Data (JSON)</span>
              </button>
              <button
                type="button"
                className="btn btn--ghost"
                style={{ width: '100%', justifyContent: 'flex-start', fontSize: '12px', padding: '6px 10px' }}
                onClick={() => handleReportAction('html')}
              >
                <FileText size={14} color="var(--color-blue-600)" />
                <span>Forensic View (HTML)</span>
              </button>
              <button
                type="button"
                className="btn btn--ghost"
                style={{ width: '100%', justifyContent: 'flex-start', fontSize: '12px', padding: '6px 10px' }}
                onClick={() => handleReportAction('pdf')}
              >
                <FileSpreadsheet size={14} color="var(--color-blue-600)" />
                <span>Official Audit (PDF)</span>
              </button>
            </div>
          )}
        </div>
      </div>

      <CaptureSelectorModal
        isOpen={showCaptureModal}
        onClose={() => setShowCaptureModal(false)}
      />
    </header>
  );
};
