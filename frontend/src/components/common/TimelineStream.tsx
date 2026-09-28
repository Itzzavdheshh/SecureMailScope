import React from 'react';
import type { TimelineEventRead } from '../../types/api';
import { SeverityBadge } from './Badge';

interface TimelineStreamProps {
  events: TimelineEventRead[];
  onEventClick?: (evt: TimelineEventRead) => void;
  selectedEventId?: string | number | null;
}

export const TimelineStream: React.FC<TimelineStreamProps> = ({
  events,
  onEventClick,
  selectedEventId,
}) => {
  if (events.length === 0) {
    return (
      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--color-text-muted)' }}>
        No timeline events recorded in this capture.
      </div>
    );
  }

  return (
    <div className="timeline-stream">
      <div
        className="timeline-stream-row"
        style={{
          background: '#F4F6F9',
          fontWeight: 700,
          color: 'var(--color-text-muted)',
          fontSize: '10px',
          textTransform: 'uppercase',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <span>TIMESTAMP</span>
        <span>EVENT TYPE</span>
        <span>FRAME #</span>
        <span>SEVERITY</span>
        <span>DETAILS</span>
      </div>

      {events.map((evt, idx) => {
        const isSelected = selectedEventId !== undefined && selectedEventId !== null && selectedEventId === (evt.id || idx);
        return (
          <div
            key={evt.id || idx}
            className={`timeline-stream-row ${isSelected ? 'selected' : ''}`}
            style={{
              background: isSelected ? 'var(--color-surface-active)' : undefined,
            }}
            onClick={() => onEventClick && onEventClick(evt)}
          >
            <span style={{ color: 'var(--color-text-muted)' }}>
              {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : `EVT-${idx + 1}`}
            </span>
            <span style={{ fontWeight: 600, color: 'var(--color-blue-700)' }}>
              {evt.event_type}
            </span>
            <span>
              {evt.frame_number ? `#${evt.frame_number}` : '-'}
            </span>
            <span>
              <SeverityBadge severity={evt.severity || 'INFO'} />
            </span>
            <span style={{ color: 'var(--color-text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {evt.summary}
            </span>
          </div>
        );
      })}
    </div>
  );
};
