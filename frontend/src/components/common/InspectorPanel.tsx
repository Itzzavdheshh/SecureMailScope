import React from 'react';
import { X } from 'lucide-react';

interface InspectorPanelProps {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: React.ReactNode;
}

export const InspectorPanel: React.FC<InspectorPanelProps> = ({
  title,
  subtitle,
  onClose,
  children,
}) => {
  return (
    <div className="inspector-panel">
      <div className="inspector-header">
        <div>
          <div className="inspector-title">{title}</div>
          {subtitle && (
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
              {subtitle}
            </div>
          )}
        </div>
        <button
          type="button"
          className="btn btn--ghost"
          style={{ padding: '2px 4px' }}
          onClick={onClose}
          title="Close Inspector"
        >
          <X size={16} />
        </button>
      </div>
      <div className="inspector-body">{children}</div>
    </div>
  );
};
