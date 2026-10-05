import { apiClient } from './client';
import type {
  AnalysisJobRead,
  BehavioralAnalysisRead,
  CaptureRead,
  CaptureUploadResponse,
  DriftEventRead,
  EmailSessionRead,
  EvidenceRead,
  FindingRead,
  InfrastructureIdentityRead,
  JobBehavioralSummary,
  PaginatedBehavioralResponse,
  PaginatedResponse,
  RiskSummaryResponse,
  SecurityFingerprintRead,
  TimelineEventRead,
} from '../types/api';

export const capturesApi = {
  upload: async (file: File): Promise<CaptureUploadResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await apiClient.post<CaptureUploadResponse>('/captures', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data;
    } catch (err: any) {
      if (err.response?.status === 409 && err.response?.data?.detail?.job_id) {
        const detail = err.response.data.detail;
        return {
          id: detail.existing_capture_id || detail.id,
          filename: detail.filename,
          file_path: detail.file_path || '',
          file_size_bytes: detail.file_size_bytes || 0,
          sha256_hash: detail.sha256_hash || '',
          total_packets: detail.total_packets || 0,
          capture_start_time: detail.capture_start_time || null,
          capture_end_time: detail.capture_end_time || null,
          status: detail.status || 'UPLOADED',
          created_at: detail.created_at || new Date().toISOString(),
          updated_at: detail.updated_at || new Date().toISOString(),
          job_id: detail.job_id,
          job_status: detail.job_status || 'PENDING',
          message: detail.message || 'Duplicate capture recognized. Ready for analysis.',
        };
      }
      throw err;
    }
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
  list: async (
    captureId?: string,
    page = 1,
    pageSize = 50,
    status?: AnalysisJobRead['status'],
  ): Promise<PaginatedResponse<AnalysisJobRead>> => {
    const res = await apiClient.get<PaginatedResponse<AnalysisJobRead>>('/jobs', {
      params: { capture_id: captureId, page, page_size: pageSize, status },
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

  fingerprint: async (sessionId: string): Promise<SecurityFingerprintRead> => {
    const res = await apiClient.get<SecurityFingerprintRead>(`/sessions/${sessionId}/fingerprint`);
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
  job_id?: string;
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
    return apiClient.getUri({
      url: `/reports/${encodeURIComponent(jobId)}`,
      params: { format },
    });
  },

  getCaptureReportUrl: (captureId: string, format: 'json' | 'html' | 'pdf'): string => {
    return apiClient.getUri({
      url: `/captures/${encodeURIComponent(captureId)}/report`,
      params: { format },
    });
  },
};

export interface BehaviorFilterParams {
  job_id?: string;
  infrastructure_id?: string;
  significant_only?: boolean;
  page?: number;
  page_size?: number;
}

export const behaviorApi = {
  list: async (params: BehaviorFilterParams = {}): Promise<PaginatedBehavioralResponse> => {
    const res = await apiClient.get<PaginatedBehavioralResponse>('/behavior', {
      params: { page: 1, page_size: 50, ...params },
    });
    return res.data;
  },

  get: async (analysisId: string): Promise<BehavioralAnalysisRead> => {
    const res = await apiClient.get<BehavioralAnalysisRead>(`/behavior/${analysisId}`);
    return res.data;
  },

  getJobSummary: async (jobId: string): Promise<JobBehavioralSummary> => {
    const res = await apiClient.get<JobBehavioralSummary>(`/behavior/jobs/${jobId}/summary`);
    return res.data;
  },
};
