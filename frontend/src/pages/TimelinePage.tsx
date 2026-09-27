import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Clock, RefreshCw, Layers } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { timelineApi } from '../api/services';
import type { TimelineEventRead } from '../types/api';
import { SeverityBadge } from '../components/common/Badge';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';

export const TimelinePage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const [events, setEvents] = useState<TimelineEventRead[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchTimeline = async () => {
    if (!activeJob) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await timelineApi.getJobTimeline(activeJob.id);
      setEvents(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch forensic timeline stream.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [activeJob]);

  if (isLoading) return <LoadingState message="Reconstructing forensic network timeline..." />;
  if (errorMsg) return <ErrorState message={errorMsg} onRetry={fetchTimeline} />;
  if (!activeJob || events.length === 0) {
    return (
      <EmptyState
        title="No Timeline Events Recorded"
        subtitle="No chronological forensic timeline events were recorded for the current analysis job."
        icon={<Clock size={40} />}
      />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Forensic Network Timeline</h2>
          <p>Chronological sequence of network events, TLS handshakes, certificate evaluations, rule violations, and drift events.</p>
        </div>
        <button onClick={fetchTimeline} className="btn btn--ghost">
          <RefreshCw size={16} /> Refresh
        </button>
      </div>

      <div className="card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', position: 'relative' }}>
          {/* Vertical Timeline Line */}
          <div
            style={{
              position: 'absolute',
              left: '19px',
              top: '10px',
              bottom: '10px',
              width: '2px',
              background: 'var(--color-border-strong)',
              zIndex: 0,
            }}
          />

          {events.map((ev, index) => (
            <div
              key={ev.id || index}
              style={{
                display: 'flex',
                gap: '16px',
                alignItems: 'flex-start',
                position: 'relative',
                zIndex: 1,
              }}
            >
              {/* Event Marker Node */}
              <div
                style={{
                  width: '40px',
                  height: '40px',
                  borderRadius: '50%',
                  background: 'var(--color-bg-secondary)',
                  border: `2px solid ${
                    ev.severity === 'CRITICAL' || ev.severity === 'HIGH'
                      ? 'var(--color-high)'
                      : ev.severity === 'MEDIUM'
                      ? 'var(--color-warning)'
                      : 'var(--color-accent-cyan)'
                  }`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <Clock
                  size={18}
                  style={{
                    color:
                      ev.severity === 'CRITICAL' || ev.severity === 'HIGH'
                        ? 'var(--color-high)'
                        : 'var(--color-accent-cyan)',
                  }}
                />
              </div>

              {/* Event Details Card */}
              <div
                style={{
                  flex: 1,
                  background: 'var(--color-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  padding: '12px 16px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="mono" style={{ fontWeight: 700, color: 'var(--color-accent-cyan)' }}>
                      {ev.event_type}
                    </span>
                    {ev.frame_number !== null && ev.frame_number !== undefined && (
                      <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                        Frame #{ev.frame_number}
                      </span>
                    )}
                    <SeverityBadge severity={ev.severity} />
                  </div>

                  <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>
                    {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                  </div>
                </div>

                <div style={{ marginTop: '6px', fontSize: '0.875rem', color: 'var(--color-text)' }}>
                  {ev.summary}
                </div>

                {ev.session_id && (
                  <div style={{ marginTop: '8px' }}>
                    <Link
                      to={`/sessions/${ev.session_id}`}
                      className="btn btn--ghost"
                      style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                    >
                      <Layers size={14} /> Open Associated Session
                    </Link>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
