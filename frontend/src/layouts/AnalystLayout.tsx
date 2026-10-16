import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
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
  Brain,
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
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={16} /> },
    { to: '/intake', label: 'Intake & PCAP', icon: <UploadCloud size={16} /> },
    { to: '/sessions', label: 'Sessions', icon: <Layers size={16} /> },
    { to: '/findings', label: 'Security Findings', icon: <ShieldCheck size={16} /> },
    { to: '/evidence', label: 'Evidence Explorer', icon: <Activity size={16} /> },
    { to: '/infrastructure', label: 'Infrastructure', icon: <Server size={16} /> },
    { to: '/drifts', label: 'Cryptographic Drift', icon: <TrendingDown size={16} /> },
    { to: '/timeline', label: 'Forensic Timeline', icon: <Clock size={16} /> },
    { to: '/behavior', label: 'Behavioural Analysis', icon: <Brain size={16} /> },
    { to: '/reports', label: 'Reports', icon: <FileText size={16} /> },
  ];

  return (
    <div className="app-shell">
      {/* Sidebar Navigation */}
      <aside className={`app-sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>

        {/* Logo / Brand */}
        <div className="sidebar-logo">
          <ShieldCheck size={22} className="sidebar-logo-icon" />
          <div>
            <div className="sidebar-logo-name">SecureMailScope</div>
            <div className="sidebar-logo-tagline">Forensic Investigation Platform</div>
          </div>
        </div>

        {/* Navigation Items */}
        <div className="sidebar-section-label">Investigation Workspaces</div>
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              onClick={() => setMobileMenuOpen(false)}
              className={({ isActive }) =>
                `sidebar-nav-item${isActive ? ' active' : ''}`
              }
            >
              <span className="sidebar-nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="sidebar-footer">
          <span>SIH 2026 · PS 26159</span>
          <span>v1.0.0</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="app-content">

        {/* Top Header Bar */}
        <header className="app-topbar">
          <button
            className="btn btn--ghost mobile-menu-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            style={{ display: 'none', marginRight: '8px' }}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>

          {/* Active Capture Context Picker */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
            <span
              style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                color: 'var(--color-text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                whiteSpace: 'nowrap',
              }}
            >
              Capture Context
            </span>
            <select
              value={activeCapture?.id || ''}
              onChange={(e) => selectCaptureById(e.target.value)}
              className="input"
              style={{ maxWidth: '280px', padding: '5px 8px', fontSize: 'var(--text-sm)' }}
            >
              {capturesList.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.filename} ({c.total_packets.toLocaleString()} pkts)
                </option>
              ))}
              {capturesList.length === 0 && <option value="">No captures ingested</option>}
            </select>

            {activeCapture && (
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  color: 'var(--color-text-muted)',
                  background: 'var(--color-bg-primary)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '2px 6px',
                }}
              >
                SHA-256: {activeCapture.sha256_hash.substring(0, 12)}…
              </span>
            )}
          </div>

          {/* Action Bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              onClick={() => navigate('/intake')}
              className="btn btn--secondary"
              style={{ padding: '5px 12px', fontSize: 'var(--text-sm)' }}
            >
              <UploadCloud size={15} />
              New PCAP
            </button>

            {/* Report Export Dropdown */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setShowReportDropdown(!showReportDropdown)}
                className="btn btn--primary"
                disabled={!activeJob}
                style={{ padding: '5px 13px', fontSize: 'var(--text-sm)' }}
              >
                <Download size={15} />
                Export Report
                <ChevronDown size={13} style={{ marginLeft: '2px' }} />
              </button>

              {showReportDropdown && activeJob && (
                <div
                  style={{
                    position: 'absolute',
                    right: 0,
                    top: 'calc(100% + 6px)',
                    backgroundColor: 'var(--color-surface)',
                    border: '1px solid var(--color-border)',
                    borderRadius: 'var(--radius-lg)',
                    boxShadow: 'var(--shadow-lg)',
                    zIndex: 'var(--z-dropdown)',
                    minWidth: '200px',
                    padding: '6px 0',
                    overflow: 'hidden',
                  }}
                >
                  {[
                    {
                      format: 'json' as const,
                      label: 'JSON Data Export',
                      icon: <FileCode size={15} style={{ color: 'var(--color-accent)' }} />,
                    },
                    {
                      format: 'html' as const,
                      label: 'HTML Report',
                      icon: <FileSpreadsheet size={15} style={{ color: 'var(--color-info)' }} />,
                    },
                    {
                      format: 'pdf' as const,
                      label: 'Download PDF Report',
                      icon: <FileText size={15} style={{ color: 'var(--color-critical)' }} />,
                    },
                  ].map(({ format, label, icon }) => (
                    <button
                      key={format}
                      onClick={() => handleReportAction(format)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        width: '100%',
                        padding: '9px 16px',
                        background: 'none',
                        border: 'none',
                        color: 'var(--color-text)',
                        fontSize: 'var(--text-sm)',
                        textAlign: 'left',
                        cursor: 'pointer',
                        transition: 'background var(--transition-fast)',
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLButtonElement).style.background =
                          'var(--color-surface-hover)';
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLButtonElement).style.background = 'none';
                      }}
                    >
                      {icon}
                      {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Dynamic Page Outlet */}
        <main className="app-page">
          <Outlet />
        </main>

        {/* Subtle forensic watermark */}
        <div className="forensic-watermark">
          SECUREMAILSCOPE · FORENSIC ANALYSIS PLATFORM · SIH-2026-PS-26159
        </div>
      </div>
    </div>
  );
};
