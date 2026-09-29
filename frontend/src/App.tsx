import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { WorkspaceProvider } from './context/WorkspaceContext';
import { AppShell } from './layouts/AppShell';

import { OverviewPage } from './pages/OverviewPage';
import { IntakePage } from './pages/IntakePage';
import { SessionsPage } from './pages/SessionsPage';
import { SessionDetailPage } from './pages/SessionDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { EvidencePage } from './pages/EvidencePage';
import { InfrastructurePage } from './pages/InfrastructurePage';
import { DriftPage } from './pages/DriftPage';
import { TimelinePage } from './pages/TimelinePage';
import { ReportsPage } from './pages/ReportsPage';
import { BehaviorPage } from './pages/BehaviorPage';
import { CaptureRegistryPage } from './pages/CaptureRegistryPage';

export function App() {
  return (
    <WorkspaceProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AppShell />}>
            <Route index element={<OverviewPage />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="captures" element={<CaptureRegistryPage />} />
            <Route path="intake" element={<IntakePage />} />
            <Route path="sessions" element={<SessionsPage />} />
            <Route path="sessions/:sessionId" element={<SessionDetailPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="infrastructure" element={<InfrastructurePage />} />
            <Route path="drifts" element={<DriftPage />} />
            <Route path="drift" element={<DriftPage />} />
            <Route path="timeline" element={<TimelinePage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="behavior" element={<BehaviorPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </WorkspaceProvider>
  );
}

export default App;
