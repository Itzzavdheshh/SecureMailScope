import React from 'react';

export interface MetricItem {
  label: string;
  value: string | number;
  highlight?: 'secure' | 'warning' | 'critical' | 'info';
}

interface MetricStripProps {
  metrics: MetricItem[];
}

export const MetricStrip: React.FC<MetricStripProps> = ({ metrics }) => {
  return (
    <div className="metric-strip">
      {metrics.map((item, idx) => (
        <React.Fragment key={item.label}>
          {idx > 0 && <div className="metric-strip-divider" />}
          <div className="metric-strip-item">
            <span className="metric-strip-label">{item.label}</span>
            <span
              className="metric-strip-value"
              style={{
                color:
                  item.highlight === 'critical'
                    ? 'var(--color-critical)'
                    : item.highlight === 'warning'
                    ? 'var(--color-warning)'
                    : item.highlight === 'secure'
                    ? 'var(--color-success)'
                    : item.highlight === 'info'
                    ? 'var(--color-blue-700)'
                    : 'inherit',
              }}
            >
              {item.value}
            </span>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
};
