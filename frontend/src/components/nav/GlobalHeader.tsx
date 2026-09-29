import React, { useState } from 'react';
import { Search, Download, ChevronDown, FileCode, FileText, FileSpreadsheet, Layers } from 'lucide-react';
import { useWorkspace } from '../../context/WorkspaceContext';
import { reportsApi } from '../../api/services';
import { CaptureSelectorModal } from './CaptureSelectorModal';

export const GlobalHeader: React.FC = () => {
  const { activeCapture, activeJob } = useWorkspace();
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
      <div className="global-header-brand">
        <span className="global-header-title">SECUREMAILSCOPE</span>
        <span className="global-header-divider" aria-hidden="true">|</span>
      </div>

      <div className="global-header-capture">
        <div className="global-header-capture-details">
          <span className="investigation-bar-label">CAPTURE:</span>
          {activeCapture ? (
            <>
              <span className="investigation-bar-file global-header-capture-name" title={activeCapture.filename}>
                {activeCapture.filename}
              </span>
              <span className="badge badge--info global-header-metadata">
                {activeCapture.total_packets ? `${activeCapture.total_packets} PKTS` : 'READY'}
              </span>
              {activeCapture.risk_band && (
                <span className={`badge ${getRiskBadgeClass(activeCapture.risk_band)} global-header-metadata`}>
                  {activeCapture.risk_band}
                </span>
              )}
            </>
          ) : (
            <span className="global-header-no-capture">No capture loaded</span>
          )}
        </div>

        <button
          type="button"
          className="btn btn--ghost global-header-change-capture"
          onClick={() => setShowCaptureModal(true)}
        >
          <Layers size={14} color="var(--color-blue-700)" />
          <span>Change Capture</span>
          <ChevronDown size={12} />
        </button>
      </div>

      <div className="global-header-right">
        <div className="command-search-input global-header-search">
          <Search size={14} aria-hidden="true" />
          <input type="text" placeholder="Search sessions, rules, IPs..." aria-label="Search sessions, rules, IPs" />
          <kbd className="global-header-shortcut">Ctrl+K</kbd>
        </div>

        <div className="global-header-export">
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
            <div className="global-header-export-menu">
              <button
                type="button"
                className="btn btn--ghost global-header-export-option"
                onClick={() => handleReportAction('json')}
              >
                <FileCode size={14} color="var(--color-blue-600)" />
                <span>Raw Data (JSON)</span>
              </button>
              <button
                type="button"
                className="btn btn--ghost global-header-export-option"
                onClick={() => handleReportAction('html')}
              >
                <FileText size={14} color="var(--color-blue-600)" />
                <span>Forensic View (HTML)</span>
              </button>
              <button
                type="button"
                className="btn btn--ghost global-header-export-option"
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
