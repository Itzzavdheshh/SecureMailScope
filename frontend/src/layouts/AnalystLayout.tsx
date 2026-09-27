import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  UploadCloud,
  LayoutDashboard,
  Layers,
  FileText,
  Activity,
  Server,
  TrendingDown,
  Clock,
  Download,
  ChevronDown,
  FileCode,
  FileSpreadsheet,
  Menu,
  X,
} from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { reportsApi } from '../api/services';

export const AnalystLayout: React.FC = () => {
  const { activeCapture, activeJob, capturesList, selectCaptureById } = useWorkspace();
  const [showReportDropdown, setShowReportDropdown] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();

  const handleReportAction = (format: 'json' | 'html' | 'pdf') => {
    if (!activeJob) return;
    const url = reportsApi.getJobReportUrl(activeJob.id, format);
    if (format === 'json' || format === 'html') {
      window.open(url, '_blank');
    } else {
      window.location.href = url;
    }
    setShowReportDropdown(false);
  };

  const navItems = [
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={18} /> },
    { to: '/intake', label: 'Intake & PCAP', icon: <UploadCloud size={18} /> },
    { to: '/sessions', label: 'Sessions Inventory', icon: <Layers size={18} /> },
    { to: '/findings', label: 'Security Findings', icon: <ShieldAlert size={18} /> },
    { to: '/evidence', label: 'Evidence Explorer', icon: <Activity size={18} /> },
    { to: '/infrastructure', label: 'Infrastructure', icon: <Server size={18} /> },
    { to: '/drifts', label: 'Cryptographic Drift', icon: <TrendingDown size={18} /> },
    { to: '/timeline', label: 'Forensic Timeline', icon: <Clock size={18} /> },
    { to: '/reports', label: 'Reports', icon: <FileText size={18} /> },
  ];

  return (
    <div className="app-shell">
      <div className="grid-overlay" />

      {/* Sidebar Navigation */}
      <aside className={`app-sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <ShieldAlert size={24} style={{ color: 'var(--color-accent-cyan)' }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem', letterSpacing: '0.02em', color: 'var(--color-text)' }}>
              SecureMailScope
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--color-accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Forensic Workspace
            </div>
          </div>
        </div>

        <nav style={{ padding: '12px var(--space-3)', flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              onClick={() => setMobileMenuOpen(false)}
              className={({ isActive }) => `btn btn--ghost ${isActive ? 'active-nav' : ''}`}
              style={({ isActive }) => ({
                justifyContent: 'flex-start',
                width: '100%',
                padding: '10px 14px',
                borderRadius: '6px',
                color: isActive ? 'var(--color-accent-cyan)' : 'var(--color-text-secondary)',
                backgroundColor: isActive ? 'var(--color-accent-cyan-glow)' : 'transparent',
                borderLeft: isActive ? '3px solid var(--color-accent-cyan)' : '3px solid transparent',
              })}
            >
              {item.icon}
              <span style={{ fontSize: '0.875rem' }}>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div
          style={{
            padding: '12px 16px',
            borderTop: '1px solid var(--color-border)',
            fontSize: '0.75rem',
            color: 'var(--color-text-tertiary)',
            display: 'flex',
            justifyContent: 'space-between',
          }}
        >
          <span>SIH 2026 PS 26159</span>
          <span>v1.0.0</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="app-content">
        {/* Top Header */}
        <header className="app-topbar">
          <button
            className="btn btn--ghost mobile-menu-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            style={{ display: 'none', marginRight: '8px' }}
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>

          {/* Active Context Picker */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Capture Context:
            </span>
            <select
              value={activeCapture?.id || ''}
              onChange={(e) => selectCaptureById(e.target.value)}
              className="input"
              style={{ maxWidth: '280px', padding: '4px 8px', fontSize: '0.85rem' }}
            >
              {capturesList.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.total_packets} pkts)
                </option>
              ))}
              {capturesList.length === 0 && <option value="">No captures ingested</option>}
            </select>

            {activeCapture && (
              <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>
                SHA-256: {activeCapture.sha256_hash.substring(0, 12)}...
              </span>
            )}
          </div>

          {/* Intake Action */}
          <button
            onClick={() => navigate('/intake')}
            className="btn btn--secondary"
            style={{ marginRight: '12px', padding: '6px 12px', fontSize: '0.8rem' }}
          >
            <UploadCloud size={16} /> New PCAP
          </button>

          {/* Report Export Menu */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setShowReportDropdown(!showReportDropdown)}
              className="btn btn--primary"
              disabled={!activeJob}
              style={{ padding: '6px 14px', fontSize: '0.8rem' }}
            >
              <Download size={16} /> Export Report <ChevronDown size={14} />
            </button>

            {showReportDropdown && activeJob && (
              <div
                style={{
                  position: 'absolute',
                  right: 0,
                  top: '100%',
                  marginTop: '6px',
                  backgroundColor: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  boxShadow: 'var(--shadow-lg)',
                  zIndex: 100,
                  minWidth: '180px',
                  padding: '4px 0',
                }}
              >
                <button
                  onClick={() => handleReportAction('json')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    width: '100%',
                    padding: '8px 14px',
                    background: 'none',
                    border: 'none',
                    color: 'var(--color-text)',
                    fontSize: '0.85rem',
                    textAlign: 'left',
                    cursor: 'pointer',
                  }}
                >
                  <FileCode size={16} style={{ color: 'var(--color-accent-cyan)' }} /> JSON Data Graph
                </button>
                <button
                  onClick={() => handleReportAction('html')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    width: '100%',
                    padding: '8px 14px',
                    background: 'none',
                    border: 'none',
                    color: 'var(--color-text)',
                    fontSize: '0.85rem',
                    textAlign: 'left',
                    cursor: 'pointer',
                  }}
                >
                  <FileSpreadsheet size={16} style={{ color: 'var(--color-accent-indigo)' }} /> Dark HTML Report
                </button>
                <button
                  onClick={() => handleReportAction('pdf')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    width: '100%',
                    padding: '8px 14px',
                    background: 'none',
                    border: 'none',
                    color: 'var(--color-text)',
                    fontSize: '0.85rem',
                    textAlign: 'left',
                    cursor: 'pointer',
                  }}
                >
                  <FileText size={16} style={{ color: 'var(--color-high)' }} /> Download PDF Report
                </button>
              </div>
            )}
          </div>
        </header>

        {/* Dynamic Page Outlet */}
        <main className="app-page">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
