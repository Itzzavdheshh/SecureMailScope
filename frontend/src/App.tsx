import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { WorkspaceProvider } from './context/WorkspaceContext';
import { AnalystLayout } from './layouts/AnalystLayout';

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

export function App() {
  return (
    <WorkspaceProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AnalystLayout />}>
            <Route index element={<OverviewPage />} />
            <Route path="intake" element={<IntakePage />} />
            <Route path="sessions" element={<SessionsPage />} />
            <Route path="sessions/:sessionId" element={<SessionDetailPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="infrastructure" element={<InfrastructurePage />} />
            <Route path="drifts" element={<DriftPage />} />
            <Route path="timeline" element={<TimelinePage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </WorkspaceProvider>
  );
}

export default App;
