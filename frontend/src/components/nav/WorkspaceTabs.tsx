import React from 'react';
import { NavLink } from 'react-router-dom';
import { useWorkspace } from '../../context/WorkspaceContext';

export const WorkspaceTabs: React.FC = () => {
  const { activeJob } = useWorkspace();

  const tabs = [
    { to: '/', label: 'Overview', count: null },
    { to: '/intake', label: 'Intake & PCAP', count: null },
    { to: '/sessions', label: 'Sessions', count: activeJob?.session_count },
    { to: '/findings', label: 'Findings', count: activeJob?.finding_count },
    { to: '/evidence', label: 'Evidence', count: null },
    { to: '/infrastructure', label: 'Infrastructure', count: null },
    { to: '/drifts', label: 'Drift', count: null },
    { to: '/timeline', label: 'Timeline', count: null },
    { to: '/reports', label: 'Reports', count: null },
  ];

  return (
    <nav className="workspace-tabs">
      {tabs.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          end={tab.to === '/'}
          className={({ isActive }) => `workspace-tab ${isActive ? 'active' : ''}`}
        >
          <span>{tab.label}</span>
          {tab.count !== null && tab.count !== undefined && (
            <span className="workspace-tab-badge">{tab.count}</span>
          )}
        </NavLink>
      ))}
    </nav>
  );
};
