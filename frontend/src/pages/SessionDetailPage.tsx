import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Lock,
  FileCheck,
  Activity,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';
import { sessionsApi } from '../api/services';
import type { EmailSessionRead } from '../types/api';
import { StarttlsStateBadge, SeverityBadge } from '../components/common/Badge';
import { LoadingState, ErrorState } from '../components/common/StateViews';

export const SessionDetailPage: React.FC = () => {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [session, setSession] = useState<EmailSessionRead | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    const fetchSession = async () => {
      setIsLoading(true);
      setErrorMsg(null);
      try {
        const res = await sessionsApi.get(sessionId);
        setSession(res);
      } catch (err: any) {
        setErrorMsg(err.message || `Failed to fetch session detail for ${sessionId}`);
      } finally {
        setIsLoading(false);
      }
    };
    fetchSession();
  }, [sessionId]);

  if (isLoading) return <LoadingState message="Loading session forensic analysis..." />;
  if (errorMsg || !session) return <ErrorState message={errorMsg || 'Session not found.'} />;

  const tls = session.tls_handshake;
  const starttls = session.starttls_details;
  const certs = session.certificates || [];
  const findings = session.findings || [];

  return (
    <div className="workspace-page-scrollable">
      {/* Top Header Navigation */}
      <div>
        <Link to="/sessions" className="btn btn--ghost" style={{ padding: '4px 0', fontSize: '0.85rem', marginBottom: '8px' }}>
          <ArrowLeft size={16} /> Back to Sessions List
        </Link>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2>Session #{session.session_index} Forensic Inspection</h2>
            <div className="mono" style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
              UUID: {session.id}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
              Session Risk Score
            </div>
            <div
              className="mono"
              style={{
                fontSize: '1.75rem',
                fontWeight: 700,
                color: (session.risk_score || 0) >= 40 ? 'var(--color-high)' : 'var(--color-success)',
              }}
            >
              {session.risk_score !== null && session.risk_score !== undefined ? session.risk_score.toFixed(1) : 'N/A'}
            </div>
          </div>
        </div>
      </div>

      {/* Network Endpoints & Protocol Banner */}
      <div className="grid-content-2">
        <div className="card">
          <h3>Network Endpoints & Protocol</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '12px', fontSize: '0.875rem' }}>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Client Endpoint:</span>{' '}
              <span className="mono">{session.client_ip}:{session.client_port}</span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Server Endpoint:</span>{' '}
              <span className="mono">{session.server_ip}:{session.server_port}</span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Hostname:</span>{' '}
              <strong style={{ color: 'var(--color-accent)' }}>{session.hostname || 'None observed'}</strong>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Protocol:</span>{' '}
              <span style={{ fontWeight: 600 }}>{session.protocol}</span>{' '}
              {session.is_tls_implicit && <span style={{ color: 'var(--color-info)' }}>(Implicit TLS)</span>}
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Traffic Volume:</span>{' '}
              <span className="mono">{session.packet_count} packets | {session.bytes_transferred.toLocaleString()} bytes</span>
            </div>
          </div>
        </div>

        {/* STARTTLS Details Card */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>STARTTLS Protocol Negotiation</h3>
            <StarttlsStateBadge state={session.starttls_state} />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '12px', fontSize: '0.875rem' }}>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Status:</span>{' '}
              <strong>{session.starttls_state}</strong>
            </div>
            {starttls ? (
              <>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Advertised Frame:</span>{' '}
                  <span className="mono">{starttls.advertised_in_frame ?? 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Command Frame:</span>{' '}
                  <span className="mono">{starttls.command_in_frame ?? 'N/A'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Response Frame & Code:</span>{' '}
                  <span className="mono">
                    Frame {starttls.response_in_frame ?? 'N/A'} (Code {starttls.response_code ?? 'N/A'})
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Downgrade Detected:</span>{' '}
                  <span style={{ color: starttls.is_downgrade_detected ? 'var(--color-high)' : 'var(--color-success)', fontWeight: 600 }}>
                    {starttls.is_downgrade_detected ? 'YES — DOWNGRADE ATTEMPT DETECTED' : 'NO'}
                  </span>
                </div>
              </>
            ) : (
              <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>
                No explicit STARTTLS command frames were observed for this session.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* TLS Handshake Inspection */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <Lock size={20} style={{ color: 'var(--color-accent)' }} />
          <h3>Negotiated TLS Security Parameters</h3>
        </div>

        {tls ? (
          <div className="grid-content-2" style={{ gap: '16px', fontSize: '0.875rem' }}>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Negotiated TLS Version:</span><br />
              <span className="mono" style={{ fontSize: '1rem', color: 'var(--color-accent)', fontWeight: 600 }}>
                {tls.negotiated_tls_version || 'Unencrypted / Plaintext'}
              </span>
            </div>

            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Negotiated Cipher Suite:</span><br />
              <span className="hash" style={{ fontSize: '0.85rem', color: 'var(--color-text)' }}>
                {tls.negotiated_cipher_suite || 'None'}
              </span>
            </div>

            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Forward Secrecy (PFS):</span><br />
              {tls.is_forward_secrecy ? (
                <span style={{ color: 'var(--color-success)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <CheckCircle size={16} /> Yes (ECDHE/DHE Key Exchange)
                </span>
              ) : (
                <span style={{ color: 'var(--color-high)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <AlertTriangle size={16} /> No Forward Secrecy
                </span>
              )}
            </div>

            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Key Exchange Group:</span><br />
              <span className="mono">
                {tls.key_exchange_group || 'N/A'} {tls.key_exchange_bits ? `(${tls.key_exchange_bits} bits)` : ''}
              </span>
            </div>

            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>SNI Hostname:</span><br />
              <span className="mono">{tls.sni_hostname || 'None'}</span>
            </div>

            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>ALPN Protocols:</span><br />
              <span className="mono">{tls.alpn_protocols || 'None'}</span>
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--color-text-muted)', padding: '16px 0' }}>
            No TLS handshake layer was observed for this unencrypted plaintext session.
          </div>
        )}
      </div>

      {/* X.509 Certificates Inspection */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <FileCheck size={20} style={{ color: 'var(--color-info)' }} />
          <h3>X.509 Certificate Chain ({certs.length})</h3>
        </div>

        {certs.length === 0 ? (
          <div style={{ color: 'var(--color-text-muted)' }}>No X.509 certificates observed for this session.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {certs.map((c, i) => (
              <div
                key={c.id}
                style={{
                  padding: '16px',
                  background: 'var(--color-bg-primary)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--color-accent)', marginBottom: '8px' }}>
                  Certificate #{i + 1} {c.is_self_signed ? '(Self-Signed)' : ''} {c.is_ca ? '(CA)' : ''}
                </div>
                <div className="grid-content-2" style={{ gap: '8px' }}>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Subject DN:</span><br />
                    <span className="mono">{c.subject_dn}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Issuer DN:</span><br />
                    <span className="mono">{c.issuer_dn}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Public Key:</span>{' '}
                    <span className="mono">{c.public_key_type} {c.public_key_size_bits} bits</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Signature Alg:</span>{' '}
                    <span className="mono">{c.signature_algorithm}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Valid at Capture:</span>{' '}
                    <span style={{ color: c.is_valid_at_capture ? 'var(--color-success)' : 'var(--color-high)', fontWeight: 600 }}>
                      {c.is_valid_at_capture ? 'VALID' : 'INVALID / EXPIRED'}
                    </span>
                  </div>
                  <div style={{ gridColumn: '1 / -1' }}>
                    <span style={{ color: 'var(--color-text-secondary)' }}>SHA-256 Fingerprint:</span><br />
                    <span className="hash">{c.sha256_fingerprint}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Session Security Findings & Evidence Linkage */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <ShieldAlert size={20} style={{ color: 'var(--color-high)' }} />
          <h3>Session Security Findings & Packet Evidence ({findings.length})</h3>
        </div>

        {findings.length === 0 ? (
          <div style={{ color: 'var(--color-text-muted)' }}>
            No security rule violations were triggered for this session.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {findings.map((f) => (
              <div
                key={f.id}
                style={{
                  padding: '16px',
                  background: 'var(--color-surface-hover)',
                  borderLeft: '4px solid var(--color-high)',
                  borderRadius: '4px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="mono" style={{ fontWeight: 700 }}>{f.rule_id}</span>
                    <SeverityBadge severity={f.severity} />
                    <strong style={{ fontSize: '0.95rem' }}>{f.title}</strong>
                  </div>
                  <Link to={`/evidence?finding_id=${f.id}`} className="btn btn--secondary" style={{ padding: '2px 8px', fontSize: '0.75rem' }}>
                    <Activity size={12} /> Trace Evidence ({f.evidence?.length || 0})
                  </Link>
                </div>

                <p style={{ fontSize: '0.85rem', marginTop: '8px', color: 'var(--color-text-secondary)' }}>
                  {f.description}
                </p>

                {f.evidence && f.evidence.length > 0 && (
                  <div style={{ marginTop: '12px', background: 'var(--color-bg-primary)', padding: '8px 12px', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                      Evidence Lineage Snippet:
                    </div>
                    {f.evidence.map((ev) => (
                      <div key={ev.id} className="mono" style={{ fontSize: '0.8rem', marginTop: '4px', color: 'var(--color-accent)' }}>
                        Frame #{ev.frame_number} [{ev.protocol_layer}] {ev.field_name} = "{ev.observed_value}"
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
