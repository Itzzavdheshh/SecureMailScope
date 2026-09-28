import React, { useState } from 'react';
import { Search, Download, ChevronDown, FileCode, FileText, FileSpreadsheet, Layers } from 'lucide-react';
import { useWorkspace } from '../../context/WorkspaceContext';
import { reportsApi } from '../../api/services';

export const GlobalHeader: React.FC = () => {
  const { activeCapture, activeJob, capturesList, selectCaptureById } = useWorkspace();
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showCaptureSelect, setShowCaptureSelect] = useState(false);

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

  return (
    <header className="global-header">
      {/* Left section: Product title & active investigation bar */}
      <div className="global-header-left">
        <span className="global-header-title">SECUREMAILSCOPE</span>
        <span style={{ color: 'var(--color-border)', fontSize: '14px' }}>|</span>

        <div className="investigation-bar">
          <span className="investigation-bar-label">CAPTURE:</span>
          {activeCapture ? (
            <>
              <span className="investigation-bar-file">{activeCapture.filename}</span>
              <span className="badge badge--info" style={{ fontSize: '10px', padding: '1px 5px' }}>
                {activeCapture.total_packets ? `${activeCapture.total_packets} PKTS` : 'READY'}
              </span>
            </>
          ) : (
            <span style={{ color: 'var(--color-text-muted)', fontStyle: 'italic' }}>No capture loaded</span>
          )}

          {capturesList.length > 1 && (
            <div style={{ position: 'relative', marginLeft: '4px' }}>
              <button
                type="button"
                className="btn btn--ghost"
                style={{ padding: '2px 6px', fontSize: '11px', gap: '2px' }}
                onClick={() => setShowCaptureSelect(!showCaptureSelect)}
              >
                Switch <ChevronDown size={12} />
              </button>
              {showCaptureSelect && (
                <div
                  style={{
                    position: 'absolute',
                    top: '100%',
                    left: 0,
                    marginTop: '4px',
                    background: 'var(--color-surface)',
                    border: '1px solid var(--color-border)',
                    borderRadius: 'var(--radius-md)',
                    boxShadow: 'var(--shadow-md)',
                    zIndex: 150,
                    minWidth: '220px',
                    padding: '4px',
                  }}
                >
                  {capturesList.map((cap) => (
                    <button
                      key={cap.id}
                      type="button"
                      onClick={() => {
                        selectCaptureById(cap.id);
                        setShowCaptureSelect(false);
                      }}
                      style={{
                        width: '100%',
                        textAlign: 'left',
                        padding: '6px 8px',
                        background: cap.id === activeCapture?.id ? 'var(--color-blue-050)' : 'transparent',
                        border: 'none',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '12px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                      }}
                    >
                      <Layers size={14} color="var(--color-blue-700)" />
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{cap.filename}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right section: Search input & Report dropdown */}
      <div className="global-header-right">
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
    </header>
  );
};
