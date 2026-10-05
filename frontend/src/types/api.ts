/**
 * API Data Models & Schemas for SecureMailScope Phase 7 Backend REST API.
 * Exactly matches backend Pydantic schemas.
 */

export type ProtocolType = 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';

// Exactly matches backend StarttlsStatus enum (app/models/enums.py)
export type StarttlsStatus =
  | 'NOT_OBSERVED'
  | 'ADVERTISED'
  | 'ATTEMPTED'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'ANOMALOUS';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory =
  | 'TLS_CRYPTO'
  | 'X509_CERT'
  | 'STARTTLS'
  | 'PROTOCOL_ANOMALY';

export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type RiskBand = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';

export type DriftEventType =
  | 'TLS_VERSION_DOWNGRADE'
  | 'WEAK_CIPHER_INTRODUCED'
  | 'STARTTLS_DISABLED'
  | 'CERT_CHANGED'
  | 'CERT_EXPIRED'
  | 'FORWARD_SECRECY_LOST'
  | 'KEY_SIZE_REDUCED'
  | 'RISK_SCORE_INCREASED';

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface CaptureRead {
  id: string;
  filename: string;
  file_path: string;
  file_size_bytes: number;
  sha256_hash: string;
  total_packets: number;
  capture_start_time?: string | null;
  capture_end_time?: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CaptureUploadResponse extends CaptureRead {
  job_id: string;
  job_status: string;
  message: string;
}

export interface AnalysisJobRead {
  id: string;
  capture_id: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  overall_risk_score?: number | null;
  risk_band?: RiskBand | null;
  total_sessions: number;
  total_findings: number;
  options_json?: string | null;
  created_at: string;
}

export interface StarttlsStateRead {
  id: string;
  session_id: string;
  observed_state: StarttlsStatus;
  advertised_in_frame?: number | null;
  command_in_frame?: number | null;
  response_in_frame?: number | null;
  response_code?: number | null;
  is_downgrade_detected: boolean;
  state_details_json?: string | null;
}

export interface TlsHandshakeRead {
  id: string;
  session_id: string;
  client_hello_frame?: number | null;
  server_hello_frame?: number | null;
  offered_tls_versions?: string | null;
  negotiated_tls_version?: string | null;
  client_cipher_suites?: string | null;
  negotiated_cipher_suite?: string | null;
  key_exchange_group?: string | null;
  key_exchange_bits?: number | null;
  is_forward_secrecy?: boolean | null;
  sni_hostname?: string | null;
  alpn_protocols?: string | null;
  handshake_status: string;
}

export interface CertificateRead {
  id: string;
  session_id: string;
  sha256_fingerprint: string;
  subject_dn: string;
  issuer_dn: string;
  san_list?: string | null;
  serial_number: string;
  not_before: string;
  not_after: string;
  is_valid_at_capture: boolean;
  public_key_type: string;
  public_key_size_bits: number;
  signature_algorithm: string;
  is_self_signed: boolean;
  is_ca: boolean;
  raw_pem?: string | null;
}

export interface EvidenceRead {
  id: string;
  finding_id: string;
  session_id?: string | null;
  capture_id?: string | null;
  frame_number: number;
  packet_timestamp?: number | string | null;
  protocol_layer: string;
  field_name: string;
  observed_value: string;
  raw_hex_snippet?: string | null;
  hex_dump_snippet?: string | null;
  source_reference?: string | null;
  description?: string | null;
  created_at: string;
}

export interface FindingRead {
  id: string;
  job_id: string;
  session_id?: string | null;
  rule_id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  impact_explanation?: string | null;
  remediation_recommendation?: string | null;
  score_contribution: number;
  confidence: Confidence;
  evidence: EvidenceRead[];
  created_at: string;
}

export interface EmailSessionRead {
  id: string;
  job_id: string;
  session_index: number;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  protocol: ProtocolType;
  is_tls_implicit: boolean;
  starttls_state: StarttlsStatus;
  start_time?: string | null;
  end_time?: string | null;
  packet_count: number;
  bytes_transferred: number;
  banner?: string | null;
  hostname?: string | null;
  risk_score?: number | null;
  tls_handshake?: TlsHandshakeRead | null;
  starttls_details?: StarttlsStateRead | null;
  certificates?: CertificateRead[] | null;
  findings?: FindingRead[] | null;
}

export interface SecurityFingerprintRead {
  fingerprint_version: string;
  identity: {
    protocol: string;
    server_ip: string;
    server_port: number;
    hostname: string | null;
    infrastructure_id: string | null;
  };
  stable_profile: {
    protocol: string | null;
    is_tls_implicit: boolean | null;
    starttls_state: string | null;
    tls_version: string | null;
    cipher_suite: string | null;
    key_exchange_group: string | null;
    forward_secrecy: boolean | null;
    offered_tls_versions: string | null;
    offered_cipher_suites: string | null;
    ja3: string | null;
    ja3s: string | null;
    certificate: {
      sha256_fingerprint: string | null;
      subject: string | null;
      issuer: string | null;
      sans: string | null;
      key_type: string | null;
      key_size_bits: number | null;
      signature_algorithm: string | null;
      valid_at_capture: boolean | null;
      self_signed: boolean | null;
      chain_status: string | null;
    };
  };
  security_posture: {
    analysis_job_risk_score: number | null;
    risk_band: RiskBand | null;
    session_risk_score: number | null;
    finding_ids: string[];
    severity_distribution: Record<string, number>;
  };
  evidence: {
    capture_id: string;
    analysis_job_id: string;
    session_id: string;
    observed_at: string | null;
    frames: {
      client_hello: number | null;
      server_hello: number | null;
      starttls_advertised: number | null;
      starttls_command: number | null;
      starttls_response: number | null;
      certificate: number | null;
      findings: number[];
    };
  };
  fingerprint_hash: string;
  hash_algorithm: string;
  hash_fields: string[];
}

export interface DriftEventRead {
  id: string;
  infrastructure_id: string;
  job_id: string;
  capture_id: string;
  event_type: DriftEventType;
  delta_description: string;
  risk_delta?: number | null;
  previous_state_json?: string | null;
  new_state_json?: string | null;
  detected_at: string;
}

export interface InfrastructureIdentityRead {
  id: string;
  ip_address: string;
  port?: number | null;
  protocol?: string | null;
  hostname?: string | null;
  organization?: string | null;
  identity_key?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_evaluated_job_id?: string | null;
  current_risk_score?: number | null;
  current_risk_band?: RiskBand | null;
  active_profile_json?: string | null;
  drift_events?: DriftEventRead[] | null;
}

export interface TimelineEventRead {
  id: string;
  job_id: string;
  session_id?: string | null;
  timestamp: string;
  frame_number?: number | null;
  event_type: string;
  summary: string;
  severity: Severity;
  details_json?: string | null;
  created_at: string;
}

export interface RiskSummaryResponse {
  capture_id: string;
  job_id: string;
  overall_risk_score: number;
  risk_band: RiskBand;
  total_sessions: number;
  total_findings: number;
  severity_distribution: Record<string, number>;
  drift_count: number;
  high_risk_session_count: number;
}

// ── Phase 10: Behavioral Analysis ─────────────────────────────────────────────

export type BaselineStatus = 'NO_BASELINE' | 'PROVISIONAL' | 'ESTABLISHED' | 'TRUSTED';
export type AnalysisMethodStatus = 'COMPLETED' | 'INSUFFICIENT_DATA' | 'NOT_APPLICABLE' | 'SKIPPED';
export type DeviationSignificance = 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
export type OverallBehavioralStatus = 'ANALYZED' | 'INSUFFICIENT_EVIDENCE';

export interface BehavioralAnomaly {
  feature: string;
  baseline_value: string | null;
  observed_value: string | null;
  change_description: string;
  significance: DeviationSignificance;
  reason: string;
  evidence_status: string;
  method: string;
  stat_method: string | null;
  stat_sample_count: number | null;
  stat_baseline_mean: number | null;
  stat_baseline_std: number | null;
  stat_observed_value_numeric: number | null;
  stat_zscore: number | null;
}

export interface StatisticalRiskAnalysis {
  method: string;
  method_status: AnalysisMethodStatus;
  sample_count: number;
  baseline_mean: number | null;
  baseline_std: number | null;
  baseline_median: number | null;
  baseline_iqr: number | null;
  observed_value: number | null;
  zscore: number | null;
  normalized_deviation: number | null;
  is_anomalous: boolean;
  interpretation: string;
}

export interface IsolationForestAnalysis {
  method_status: AnalysisMethodStatus;
  model_name: string;
  feature_set: string[];
  observation_count: number;
  min_required: number;
  anomaly_score: number | null;
  normalized_anomaly_score: number | null;
  is_anomalous: boolean | null;
  interpretation: string;
}

export interface BehavioralAnalysisRead {
  id: string;
  infrastructure_id: string;
  job_id: string;
  session_id: string | null;
  identity_key: string;
  baseline_status: BaselineStatus;
  observation_count: number;
  overall_status: OverallBehavioralStatus;
  significant_deviation_detected: boolean;
  deviation_summary: string;
  anomaly_count: number;
  anomalies: BehavioralAnomaly[];
  risk_stat_analysis: StatisticalRiskAnalysis | null;
  isolation_forest: IsolationForestAnalysis | null;
  limitations: string[];
  analyzed_at: string;
}

export interface PaginatedBehavioralResponse {
  items: BehavioralAnalysisRead[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface JobBehavioralSummary {
  job_id: string;
  total_analyses: number;
  significant_deviations: number;
  insufficient_data: number;
  total_anomalies: number;
  analyses: BehavioralAnalysisRead[];
}
