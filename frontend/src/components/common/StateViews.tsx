import React from 'react';
import { AlertTriangle, Database, Loader2 } from 'lucide-react';

export const LoadingState: React.FC<{ message?: string }> = ({ message = 'Loading forensic evidence...' }) => {
  return (
    <div className="empty-state" style={{ minHeight: '240px' }}>
      <Loader2 className="empty-state__icon spinner" size={32} style={{ animation: 'spin 1s linear infinite', color: 'var(--color-accent)' }} />
      <div className="empty-state__title" style={{ marginTop: '12px' }}>{message}</div>
    </div>
  );
};

export const EmptyState: React.FC<{ title?: string; subtitle?: string; icon?: React.ReactNode }> = ({
  title = 'No Data Observed',
  subtitle = 'No records match the current capture or search filter parameters.',
  icon = <Database size={40} />,
}) => {
  return (
    <div className="empty-state" style={{ minHeight: '260px' }}>
      <div className="empty-state__icon">{icon}</div>
      <div className="empty-state__title">{title}</div>
      <div className="empty-state__subtitle">{subtitle}</div>
    </div>
  );
};

export const ErrorState: React.FC<{ title?: string; message: string; onRetry?: () => void }> = ({
  title = 'Unable to Load Data',
  message,
  onRetry,
}) => {
  return (
    <div className="error-banner" style={{ margin: '16px 0', flexDirection: 'column', gap: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600 }}>
        <AlertTriangle size={18} />
        <span>{title}</span>
      </div>
      <div style={{ fontSize: '0.875rem' }}>{message}</div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="btn btn--secondary"
          style={{ marginTop: '8px', alignSelf: 'flex-start', padding: '4px 12px', fontSize: '0.75rem' }}
        >
          Retry Request
        </button>
      )}
    </div>
  );
};
