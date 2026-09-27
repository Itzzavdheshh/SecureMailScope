import { apiClient } from './client';
import type {
  AnalysisJobRead,
  CaptureRead,
  CaptureUploadResponse,
  DriftEventRead,
  EmailSessionRead,
  EvidenceRead,
  FindingRead,
  InfrastructureIdentityRead,
  PaginatedResponse,
  RiskSummaryResponse,
  TimelineEventRead,
} from '../types/api';

export const capturesApi = {
  upload: async (file: File): Promise<CaptureUploadResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post<CaptureUploadResponse>('/captures', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },

  list: async (page = 1, pageSize = 50): Promise<PaginatedResponse<CaptureRead>> => {
    const res = await apiClient.get<PaginatedResponse<CaptureRead>>('/captures', {
      params: { page, page_size: pageSize },
    });
    return res.data;
  },

  get: async (captureId: string): Promise<CaptureRead> => {
    const res = await apiClient.get<CaptureRead>(`/captures/${captureId}`);
    return res.data;
  },
};

export const jobsApi = {
  list: async (captureId?: string, page = 1, pageSize = 50): Promise<PaginatedResponse<AnalysisJobRead>> => {
    const res = await apiClient.get<PaginatedResponse<AnalysisJobRead>>('/jobs', {
      params: { capture_id: captureId, page, page_size: pageSize },
    });
    return res.data;
  },

  get: async (jobId: string): Promise<AnalysisJobRead> => {
    const res = await apiClient.get<AnalysisJobRead>(`/jobs/${jobId}`);
    return res.data;
  },

  start: async (jobId: string): Promise<{ job: AnalysisJobRead; message: string }> => {
    const res = await apiClient.post<{ job: AnalysisJobRead; message: string }>(`/jobs/${jobId}/start`);
    return res.data;
  },
};

export interface SessionFilterParams {
  capture_id?: string;
  job_id?: string;
  protocol?: string;
  server_ip?: string;
  server_port?: number;
  hostname?: string;
  tls_version?: string;
  cipher?: string;
  starttls_state?: string;
  min_risk?: number;
  max_risk?: number;
  page?: number;
  page_size?: number;
}

export const sessionsApi = {
  list: async (params: SessionFilterParams = {}): Promise<PaginatedResponse<EmailSessionRead>> => {
    const res = await apiClient.get<PaginatedResponse<EmailSessionRead>>('/sessions', {
      params: {
        page: 1,
        page_size: 50,
        ...params,
      },
    });
    return res.data;
  },

  get: async (sessionId: string): Promise<EmailSessionRead> => {
    const res = await apiClient.get<EmailSessionRead>(`/sessions/${sessionId}`);
    return res.data;
  },

  timeline: async (sessionId: string): Promise<TimelineEventRead[]> => {
    const res = await apiClient.get<TimelineEventRead[]>(`/sessions/${sessionId}/timeline`);
    return res.data;
  },
};

export interface FindingFilterParams {
  job_id?: string;
  session_id?: string;
  capture_id?: string;
  severity?: string;
  category?: string;
  confidence?: string;
  rule_id?: string;
  page?: number;
  page_size?: number;
}

export const findingsApi = {
  list: async (params: FindingFilterParams = {}): Promise<PaginatedResponse<FindingRead>> => {
    const res = await apiClient.get<PaginatedResponse<FindingRead>>('/findings', {
      params: {
        page: 1,
        page_size: 50,
        ...params,
      },
    });
    return res.data;
  },

  get: async (findingId: string): Promise<FindingRead> => {
    const res = await apiClient.get<FindingRead>(`/findings/${findingId}`);
    return res.data;
  },
};

export interface EvidenceFilterParams {
  finding_id?: string;
  session_id?: string;
  capture_id?: string;
  frame_number?: number;
  protocol_layer?: string;
  field_name?: string;
  page?: number;
  page_size?: number;
}

export const evidenceApi = {
  list: async (params: EvidenceFilterParams = {}): Promise<PaginatedResponse<EvidenceRead>> => {
    const res = await apiClient.get<PaginatedResponse<EvidenceRead>>('/evidence', {
      params: {
        page: 1,
        page_size: 50,
        ...params,
      },
    });
    return res.data;
  },

  get: async (evidenceId: string): Promise<EvidenceRead> => {
    const res = await apiClient.get<EvidenceRead>(`/evidence/${evidenceId}`);
    return res.data;
  },
};

export const infrastructureApi = {
  list: async (page = 1, pageSize = 50): Promise<PaginatedResponse<InfrastructureIdentityRead>> => {
    const res = await apiClient.get<PaginatedResponse<InfrastructureIdentityRead>>('/infrastructure', {
      params: { page, page_size: pageSize },
    });
    return res.data;
  },

  get: async (identityId: string): Promise<InfrastructureIdentityRead> => {
    const res = await apiClient.get<InfrastructureIdentityRead>(`/infrastructure/${identityId}`);
    return res.data;
  },
};

export interface DriftFilterParams {
  infrastructure_id?: string;
  job_id?: string;
  capture_id?: string;
  event_type?: string;
  page?: number;
  page_size?: number;
}

export const driftsApi = {
  list: async (params: DriftFilterParams = {}): Promise<PaginatedResponse<DriftEventRead>> => {
    const res = await apiClient.get<PaginatedResponse<DriftEventRead>>('/drifts', {
      params: {
        page: 1,
        page_size: 50,
        ...params,
      },
    });
    return res.data;
  },

  get: async (driftId: string): Promise<DriftEventRead> => {
    const res = await apiClient.get<DriftEventRead>(`/drifts/${driftId}`);
    return res.data;
  },
};

export const timelineApi = {
  getJobTimeline: async (jobId: string): Promise<TimelineEventRead[]> => {
    const res = await apiClient.get<TimelineEventRead[]>(`/jobs/${jobId}/timeline`);
    return res.data;
  },
};

export const riskApi = {
  getCaptureRisk: async (captureId: string): Promise<RiskSummaryResponse> => {
    const res = await apiClient.get<RiskSummaryResponse>(`/captures/${captureId}/risk`);
    return res.data;
  },

  getJobRisk: async (jobId: string): Promise<RiskSummaryResponse> => {
    const res = await apiClient.get<RiskSummaryResponse>(`/jobs/${jobId}/risk`);
    return res.data;
  },
};

export const reportsApi = {
  getJobReportUrl: (jobId: string, format: 'json' | 'html' | 'pdf'): string => {
    return `/api/v1/reports/${jobId}?format=${format}`;
  },

  getCaptureReportUrl: (captureId: string, format: 'json' | 'html' | 'pdf'): string => {
    return `/api/v1/captures/${captureId}/report?format=${format}`;
  },
};
