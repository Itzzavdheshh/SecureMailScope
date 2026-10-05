import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import type { CaptureRead, AnalysisJobRead } from '../types/api';
import { capturesApi, jobsApi } from '../api/services';

export interface EnrichedCapture extends CaptureRead {
  job_id?: string;
  job_status?: string;
  total_sessions?: number;
  total_findings?: number;
  overall_risk_score?: number | null;
  risk_band?: string | null;
}

interface WorkspaceContextType {
  investigationName: string;
  activeCapture: EnrichedCapture | null;
  activeJob: AnalysisJobRead | null;
  capturesList: EnrichedCapture[];
  isLoadingCaptures: boolean;
  setActiveCapture: (capture: EnrichedCapture | null) => void;
  setActiveJob: (job: AnalysisJobRead | null) => void;
  refreshCaptures: () => Promise<void>;
  selectCaptureById: (captureId: string) => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined);

export const WorkspaceProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const investigationName = "SecureMail Demo Investigation";
  const [activeCapture, setActiveCapture] = useState<EnrichedCapture | null>(null);
  const [activeJob, setActiveJob] = useState<AnalysisJobRead | null>(null);
  const [capturesList, setCapturesList] = useState<EnrichedCapture[]>([]);
  const [isLoadingCaptures, setIsLoadingCaptures] = useState<boolean>(true);
  const selectionRequest = useRef(0);

  const enrichCaptures = async (items: CaptureRead[]): Promise<EnrichedCapture[]> => {
    return Promise.all(
      items.map(async (cap) => {
        try {
          const jobsRes = await jobsApi.list(cap.id, 1, 10);
          // Prefer most recent COMPLETED job; fallback to most recent any-status.
          const completedJob = jobsRes.items.find((j) => j.status === 'COMPLETED') ?? null;
          const latestJob = completedJob ?? (jobsRes.items.length > 0 ? jobsRes.items[0] : null);
          return {
            ...cap,
            job_id: latestJob?.id,
            job_status: latestJob?.status,
            total_sessions: latestJob?.total_sessions ?? 0,
            total_findings: latestJob?.total_findings ?? 0,
            overall_risk_score: latestJob?.overall_risk_score ?? null,
            risk_band: latestJob?.risk_band ?? null,
          };
        } catch {
          return cap;
        }
      })
    );
  };

  const refreshCaptures = async () => {
    const requestId = ++selectionRequest.current;
    setIsLoadingCaptures(true);
    try {
      const res = await capturesApi.list(1, 100);
      const enriched = await enrichCaptures(res.items);
      if (requestId !== selectionRequest.current) return;
      setCapturesList(enriched);

      // Check URL search params for capture_id
      const urlParams = new URLSearchParams(window.location.search);
      const targetCaptureId = urlParams.get('capture');

      if (targetCaptureId) {
        const found = enriched.find((c) => c.id === targetCaptureId);
        if (found) {
          const jobs = await jobsApi.list(found.id, 1, 10);
          if (requestId !== selectionRequest.current) return;
          const bestJob = jobs.items.find((j) => j.status === 'COMPLETED') ?? jobs.items[0] ?? null;
          setActiveCapture(found);
          setActiveJob(bestJob);
          return;
        }
      }

      const retained = activeCapture && enriched.find((item) => item.id === activeCapture.id);
      const target = retained ?? enriched[0] ?? null;
      if (target) {
        const jobs = await jobsApi.list(target.id, 1, 10);
        if (requestId !== selectionRequest.current) return;
        const bestJob = jobs.items.find((j) => j.status === 'COMPLETED') ?? jobs.items[0] ?? null;
        setActiveCapture(target);
        setActiveJob(bestJob);
      } else {
        setActiveCapture(null);
        setActiveJob(null);
      }
    } catch (err) {
      console.error('Failed to load captures list:', err);
    } finally {
      if (requestId === selectionRequest.current) setIsLoadingCaptures(false);
    }
  };

  const selectCaptureById = async (captureId: string) => {
    const requestId = ++selectionRequest.current;
    setActiveCapture(null);
    setActiveJob(null);
    try {
      const cap = await capturesApi.get(captureId);
      const jobs = await jobsApi.list(captureId, 1, 10);
      if (requestId !== selectionRequest.current) return;
      const completedJobC = jobs.items.find((j) => j.status === 'COMPLETED') ?? null;
      const latestJob = completedJobC ?? (jobs.items.length > 0 ? jobs.items[0] : null);

      const enrichedCap: EnrichedCapture = {
        ...cap,
        job_id: latestJob?.id,
        job_status: latestJob?.status,
        total_sessions: latestJob?.total_sessions ?? 0,
        total_findings: latestJob?.total_findings ?? 0,
        overall_risk_score: latestJob?.overall_risk_score ?? null,
        risk_band: latestJob?.risk_band ?? null,
      };

      setActiveCapture(enrichedCap);
      setActiveJob(latestJob);

      // Update URL query string without full page reload
      const url = new URL(window.location.href);
      url.searchParams.set('capture', captureId);
      window.history.pushState({}, '', url.toString());
    } catch (err) {
      if (requestId === selectionRequest.current) {
        console.error(`Failed to select capture ${captureId}:`, err);
      }
    }
  };

  useEffect(() => {
    refreshCaptures();
  }, []);

  return (
    <WorkspaceContext.Provider
      value={{
        investigationName,
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
