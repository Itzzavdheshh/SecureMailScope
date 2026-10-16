import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, ChevronRight, FolderCheck } from 'lucide-react';
import { useWorkspace } from '../../context/WorkspaceContext';

interface CaptureSelectorModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CaptureSelectorModal: React.FC<CaptureSelectorModalProps> = ({ isOpen, onClose }) => {
  const { investigationName, activeCapture, capturesList, selectCaptureById } = useWorkspace();
  const [searchTerm, setSearchTerm] = useState('');
  const navigate = useNavigate();

  if (!isOpen) return null;

  const filteredCaptures = capturesList.filter((cap) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      cap.filename.toLowerCase().includes(term) ||
      cap.id.toLowerCase().includes(term) ||
      cap.sha256_hash.toLowerCase().includes(term) ||
      (cap.risk_band && cap.risk_band.toLowerCase().includes(term))
    );
  });

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
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(3px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '16px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '680px',
          maxHeight: '85vh',
          backgroundColor: 'var(--color-surface, #ffffff)',
          border: '1px solid var(--color-border)',
          borderRadius: 'var(--radius-lg, 8px)',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            backgroundColor: 'var(--color-bg-primary, #f8fafc)',
          }}
        >
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.05em', color: 'var(--color-blue-700)', textTransform: 'uppercase' }}>
              INVESTIGATION REGISTRY SELECTOR
            </div>
            <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text)', marginTop: '2px' }}>
              {investigationName}
            </div>
          </div>
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px', borderRadius: '4px' }}
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>

        {/* Search Bar */}
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--color-border)' }}>
          <div className="command-search-input" style={{ width: '100%' }}>
            <Search size={14} />
            <input
              type="text"
              placeholder="Search captures by filename, SHA-256 hash, ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              autoFocus
            />
          </div>
        </div>

        {/* Captures List */}
        <div style={{ overflowY: 'auto', padding: '12px 20px', flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {filteredCaptures.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '13px' }}>
              No captures match your search criteria.
            </div>
          ) : (
            filteredCaptures.map((cap) => {
              const isActive = cap.id === activeCapture?.id;
              return (
                <div
                  key={cap.id}
                  onClick={() => {
                    selectCaptureById(cap.id);
                    onClose();
                  }}
                  style={{
                    padding: '12px 16px',
                    borderRadius: 'var(--radius-md, 6px)',
                    border: isActive ? '2px solid var(--color-blue-600)' : '1px solid var(--color-border)',
                    backgroundColor: isActive ? 'rgba(59, 130, 246, 0.05)' : 'var(--color-surface)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span className="mono" style={{ fontWeight: 700, fontSize: '13px', color: 'var(--color-blue-700)' }}>
                        {cap.filename}
                      </span>
                      {isActive && (
                        <span className="badge badge--info" style={{ fontSize: '10px', padding: '1px 6px' }}>
                          ACTIVE WORKSPACE
                        </span>
                      )}
                      {cap.risk_band && (
                        <span className={`badge ${getRiskBadgeClass(cap.risk_band)}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                          {cap.risk_band} ({cap.overall_risk_score !== null && cap.overall_risk_score !== undefined ? cap.overall_risk_score.toFixed(1) : 'N/A'})
                        </span>
                      )}
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '4px', display: 'flex', gap: '12px' }}>
                      <span>{cap.total_packets || 0} packets</span>
                      <span>•</span>
                      <span>{cap.total_sessions || 0} sessions</span>
                      <span>•</span>
                      <span>{cap.total_findings || 0} findings</span>
                      <span>•</span>
                      <span className="mono" style={{ fontSize: '10px' }}>ID: {cap.id.substring(0, 8)}...</span>
                    </div>
                  </div>

                  <ChevronRight size={16} color="var(--color-text-muted)" />
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '12px 20px',
            borderTop: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-bg-primary, #f8fafc)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
            Showing {filteredCaptures.length} of {capturesList.length} ingested captures
          </span>
          <button
            type="button"
            className="btn btn--primary"
            style={{ fontSize: '12px', gap: '6px' }}
            onClick={() => {
              onClose();
              navigate('/captures');
            }}
          >
            <FolderCheck size={14} />
            <span>Open Capture Registry</span>
          </button>
        </div>
      </div>
    </div>
  );
};
