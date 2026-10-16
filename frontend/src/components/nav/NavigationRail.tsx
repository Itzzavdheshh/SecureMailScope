import React from 'react';
import { NavLink } from 'react-router-dom';
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
} from 'lucide-react';

interface NavigationRailProps {
  onExportClick?: () => void;
}

export const NavigationRail: React.FC<NavigationRailProps> = ({ onExportClick }) => {
  const railItems = [
    { to: '/', label: 'Overview Command Center', icon: <LayoutDashboard size={18} /> },
    { to: '/intake', label: 'Capture Intake & Validation', icon: <UploadCloud size={18} /> },
    { to: '/sessions', label: 'Session Inventory', icon: <Layers size={18} /> },
    { to: '/findings', label: 'Security Findings Register', icon: <ShieldCheck size={18} /> },
    { to: '/evidence', label: 'Forensic Evidence Explorer', icon: <Activity size={18} /> },
    { to: '/infrastructure', label: 'Infrastructure Register', icon: <Server size={18} /> },
    { to: '/drifts', label: 'Cryptographic Drift Inspector', icon: <TrendingDown size={18} /> },
    { to: '/timeline', label: 'Forensic Timeline', icon: <Clock size={18} /> },
    { to: '/reports', label: 'Document Center & Reports', icon: <FileText size={18} /> },
  ];

  return (
    <aside className="nav-rail">
      {/* Brand Icon */}
      <div className="nav-rail-logo" title="SecureMailScope — Forensic Platform">
        <ShieldCheck size={22} />
      </div>

      {/* Navigation Icons */}
      <div className="nav-rail-items">
        {railItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) => `nav-rail-item ${isActive ? 'active' : ''}`}
            data-tooltip={item.label}
          >
            {item.icon}
          </NavLink>
        ))}
      </div>

      {/* Footer / Export Quick Action */}
      <div className="nav-rail-footer">
        <button
          className="nav-rail-item"
          onClick={onExportClick}
          data-tooltip="Export Forensic Artifacts"
          type="button"
        >
          <Download size={18} />
        </button>
      </div>
    </aside>
  );
};
