import React, { createContext, useContext, useState, useEffect } from 'react';
import type { CaptureRead, AnalysisJobRead } from '../types/api';
import { capturesApi, jobsApi } from '../api/services';

interface WorkspaceContextType {
  activeCapture: CaptureRead | null;
  activeJob: AnalysisJobRead | null;
  capturesList: CaptureRead[];
  isLoadingCaptures: boolean;
  setActiveCapture: (capture: CaptureRead | null) => void;
  setActiveJob: (job: AnalysisJobRead | null) => void;
  refreshCaptures: () => Promise<void>;
  selectCaptureById: (captureId: string) => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined);

export const WorkspaceProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeCapture, setActiveCapture] = useState<CaptureRead | null>(null);
  const [activeJob, setActiveJob] = useState<AnalysisJobRead | null>(null);
  const [capturesList, setCapturesList] = useState<CaptureRead[]>([]);
  const [isLoadingCaptures, setIsLoadingCaptures] = useState<boolean>(true);

  const refreshCaptures = async () => {
    setIsLoadingCaptures(true);
    try {
      const res = await capturesApi.list(1, 50);
      setCapturesList(res.items);
      if (res.items.length > 0 && !activeCapture) {
        const latest = res.items[0];
        setActiveCapture(latest);
        // Fetch latest job for capture
        const jobs = await jobsApi.list(latest.id, 1, 1);
        if (jobs.items.length > 0) {
          setActiveJob(jobs.items[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load captures list:', err);
    } finally {
      setIsLoadingCaptures(false);
    }
  };

  const selectCaptureById = async (captureId: string) => {
    try {
      const cap = await capturesApi.get(captureId);
      setActiveCapture(cap);
      const jobs = await jobsApi.list(captureId, 1, 1);
      if (jobs.items.length > 0) {
        setActiveJob(jobs.items[0]);
      } else {
        setActiveJob(null);
      }
    } catch (err) {
      console.error(`Failed to select capture ${captureId}:`, err);
    }
  };

  useEffect(() => {
    refreshCaptures();
  }, []);

  return (
    <WorkspaceContext.Provider
      value={{
        activeCapture,
        activeJob,
        capturesList,
        isLoadingCaptures,
        setActiveCapture,
        setActiveJob,
        refreshCaptures,
        selectCaptureById,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  );
};

export const useWorkspace = () => {
  const context = useContext(WorkspaceContext);
  if (!context) {
    throw new Error('useWorkspace must be used within a WorkspaceProvider');
  }
  return context;
};
