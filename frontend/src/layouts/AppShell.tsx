import React from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { NavigationRail } from '../components/nav/NavigationRail';
import { GlobalHeader } from '../components/nav/GlobalHeader';
import { WorkspaceTabs } from '../components/nav/WorkspaceTabs';

export const AppShell: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="app-shell-v2">
      {/* 48px Compact Icon Rail */}
      <NavigationRail onExportClick={() => navigate('/reports')} />

      {/* Main Workspace Area */}
      <div className="app-main-area">
        {/* Top Global Investigation Header */}
        <GlobalHeader />

        {/* Workspace Tab Bar */}
        <WorkspaceTabs />

        {/* Dynamic Page Workspace Content */}
        <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
};
