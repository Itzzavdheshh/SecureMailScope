import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  accentColor?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtext,
  icon,
  accentColor = 'var(--color-accent-cyan)',
}) => {
  return (
    <div className="card" style={{ borderLeft: `3px solid ${accentColor}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="stat-label" style={{ color: 'var(--color-text-secondary)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {label}
          </div>
          <div className="stat" style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text)', marginTop: '4px' }}>
            {value}
          </div>
          {subtext && (
            <div style={{ fontSize: '0.8rem', color: 'var(--color-text-tertiary)', marginTop: '4px' }}>
              {subtext}
            </div>
          )}
        </div>
        {icon && <div style={{ color: accentColor, opacity: 0.8 }}>{icon}</div>}
      </div>
    </div>
  );
};
