import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, RefreshCw, ExternalLink } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { timelineApi } from '../api/services';
import type { TimelineEventRead } from '../types/api';
import { LoadingState, EmptyState, ErrorState } from '../components/common/StateViews';
import { FilterToolbar, type FilterOption } from '../components/common/FilterToolbar';
import { TimelineStream } from '../components/common/TimelineStream';
import { InspectorPanel } from '../components/common/InspectorPanel';

export const TimelinePage: React.FC = () => {
  const { activeJob } = useWorkspace();
  const navigate = useNavigate();
  const [events, setEvents] = useState<TimelineEventRead[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEventRead | null>(null);
  const [searchVal, setSearchVal] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
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
      if (res.length > 0 && !selectedEvent) {
        setSelectedEvent(res[0]);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch forensic timeline stream.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [activeJob]);

  const filterOptions: FilterOption[] = [
    {
      key: 'severity',
      label: 'Severity',
      value: severityFilter,
      options: [
        { label: 'CRITICAL', value: 'CRITICAL' },
        { label: 'HIGH', value: 'HIGH' },
        { label: 'MEDIUM', value: 'MEDIUM' },
        { label: 'LOW', value: 'LOW' },
        { label: 'INFO', value: 'INFO' },
      ],
      onChange: (val) => setSeverityFilter(val),
    },
  ];

  const filteredEvents = events.filter((ev) => {
    if (severityFilter && ev.severity !== severityFilter) return false;
    if (!searchVal) return true;
    const term = searchVal.toLowerCase();
    return (
      ev.event_type.toLowerCase().includes(term) ||
      (ev.summary && ev.summary.toLowerCase().includes(term)) ||
      String(ev.frame_number).includes(term)
    );
  });

  return (
    <div className="workspace-page">
      {/* Filter Toolbar */}
      <FilterToolbar
        searchPlaceholder="Filter event type, summary, frame..."
        searchValue={searchVal}
        onSearchChange={(val) => setSearchVal(val)}
        filters={filterOptions}
        onReset={() => {
          setSearchVal('');
          setSeverityFilter('');
        }}
        actionButton={
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '4px 8px', fontSize: '12px' }}
            onClick={fetchTimeline}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      {/* Main Master/Detail Layout */}
      {isLoading ? (
        <LoadingState message="Reconstructing dense forensic timeline stream..." />
      ) : errorMsg ? (
        <ErrorState message={errorMsg} onRetry={fetchTimeline} />
      ) : !activeJob || events.length === 0 ? (
        <EmptyState
          title="No Timeline Events Recorded"
          subtitle="No chronological forensic timeline events were recorded for the current analysis job."
          icon={<Clock size={36} />}
        />
      ) : (
        <div className="master-detail-container">
          {/* Dense Timeline Event Stream */}
          <div className="master-pane">
            <TimelineStream
              events={filteredEvents}
              selectedEventId={selectedEvent?.id}
              onEventClick={(evt) => setSelectedEvent(evt as TimelineEventRead)}
            />
          </div>

          {/* Right Inspector Panel */}
          {selectedEvent && (
            <InspectorPanel
              title={`EVENT: ${selectedEvent.event_type}`}
              subtitle={`Timestamp: ${selectedEvent.timestamp ? new Date(selectedEvent.timestamp).toLocaleTimeString() : 'N/A'}`}
              onClose={() => setSelectedEvent(null)}
            >
              <div className="inspector-section">
                <div className="inspector-section-title">EVENT SUMMARY</div>
                <div style={{ fontSize: '12px', color: 'var(--color-text)', lineHeight: 1.4 }}>
                  {selectedEvent.summary}
                </div>
              </div>

              <div className="inspector-section">
                <div className="inspector-section-title">METADATA</div>
                <div className="detail-row">
                  <div className="detail-row__label">Severity</div>
                  <div className="detail-row__value mono" style={{ fontWeight: 700 }}>
                    {selectedEvent.severity || 'INFO'}
                  </div>
                </div>
                <div className="detail-row">
                  <div className="detail-row__label">Frame Number</div>
                  <div className="detail-row__value mono">
                    {selectedEvent.frame_number ? `#${selectedEvent.frame_number}` : 'N/A'}
                  </div>
                </div>
              </div>

              {selectedEvent.details_json && (
                <div className="inspector-section">
                  <div className="inspector-section-title">EVENT PAYLOAD</div>
                  <pre
                    style={{
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      padding: '8px',
                      background: 'var(--color-surface-inset)',
                      borderRadius: 'var(--radius-sm)',
                      maxHeight: '160px',
                      overflowY: 'auto',
                    }}
                  >
                    {selectedEvent.details_json}
                  </pre>
                </div>
              )}

              <div style={{ marginTop: 'auto', paddingTop: '12px' }}>
                {selectedEvent.session_id ? (
                  <button
                    type="button"
                    className="btn btn--primary"
                    style={{ width: '100%', justifyContent: 'center', fontSize: '12px', gap: '6px' }}
                    onClick={() => navigate(`/sessions/${selectedEvent.session_id}`)}
                  >
                    <ExternalLink size={14} />
                    <span>Open Associated Mail Session</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn btn--secondary"
                    style={{ width: '100%', justifyContent: 'center', fontSize: '12px', opacity: 0.6 }}
                    disabled
                  >
                    No Session Link
                  </button>
                )}
              </div>
            </InspectorPanel>
          )}
        </div>
      )}
    </div>
  );
};
