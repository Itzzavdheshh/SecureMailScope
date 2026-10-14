import React from 'react';

interface ComparisonPanelProps {
  title: string;
  baseline: Record<string, any>;
  current: Record<string, any>;
  diffKeys?: string[];
}

export const ComparisonPanel: React.FC<ComparisonPanelProps> = ({
  title,
  baseline,
  current,
}) => {
  const allKeys = Array.from(new Set([...Object.keys(baseline || {}), ...Object.keys(current || {})]));

  return (
    <div className="comparison-panel">
      <div style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>
        {title}
      </div>

      <div className="comparison-grid">
        {/* Baseline Box */}
        <div className="comparison-box">
          <div className="comparison-box-title" style={{ color: 'var(--color-success)' }}>
            BASELINE PROFILE
          </div>
          {allKeys.length === 0 ? (
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>No baseline data</div>
          ) : (
            allKeys.map((k) => (
              <div key={k} style={{ fontSize: '11px', display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--color-text-muted)' }}>{k}:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>
                  {String(baseline[k] ?? 'N/A')}
                </span>
              </div>
            ))
          )}
        </div>

        {/* Current Box */}
        <div className="comparison-box">
          <div className="comparison-box-title" style={{ color: 'var(--color-high)' }}>
            OBSERVED PROFILE
          </div>
          {allKeys.length === 0 ? (
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>No current data</div>
          ) : (
            allKeys.map((k) => {
              const bVal = String(baseline[k] ?? '');
              const cVal = String(current[k] ?? '');
              const isDiff = bVal !== cVal;
              return (
                <div
                  key={k}
                  style={{
                    fontSize: '11px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    background: isDiff ? 'var(--color-critical-bg)' : undefined,
                    padding: isDiff ? '1px 4px' : undefined,
                    borderRadius: '2px',
                  }}
                >
                  <span style={{ color: isDiff ? 'var(--color-critical)' : 'var(--color-text-muted)' }}>
                    {k}:
                  </span>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: isDiff ? 700 : 500,
                      color: isDiff ? 'var(--color-critical)' : 'inherit',
                    }}
                  >
                    {cVal || 'N/A'}
                  </span>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
