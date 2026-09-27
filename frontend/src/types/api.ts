/**
 * API Data Models & Schemas for SecureMailScope Phase 7 Backend REST API.
 * Exactly matches backend Pydantic schemas.
 */

export type ProtocolType = 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';

export type StarttlsStatus =
  | 'NOT_OBSERVED'
  | 'ADVERTISED'
  | 'ATTEMPTED'
  | 'ESTABLISHED'
  | 'REJECTED'
  | 'DISABLED'
  | 'CLEARTEXT_FALLBACK';

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
  start_time?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  overall_risk_score?: number | null;
  risk_band?: RiskBand | null;
  session_count: number;
  finding_count: number;
  created_at: string;
  updated_at: string;
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
  packet_timestamp?: string | null;
  protocol_layer: string;
  field_name: string;
  observed_value: string;
  raw_hex_snippet?: string | null;
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
  port: number;
  protocol: ProtocolType;
  hostname?: string | null;
  identity_key: string;
  first_seen_at: string;
  last_seen_at: string;
  last_evaluated_job_id?: string | null;
  current_risk_score?: number | null;
  active_profile_json?: string | null;
  drift_events?: DriftEventRead[] | null;
  created_at: string;
  updated_at: string;
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
