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
  accentColor = 'var(--color-accent)',
}) => {
  return (
    <div className="stat-card">
      {/* Left accent bar */}
      <div
        className="stat-card__accent-bar"
        style={{ background: accentColor }}
      />

      {/* Background icon watermark */}
      {icon && (
        <div className="stat-card__icon" style={{ color: accentColor }}>
          {icon}
        </div>
      )}

      {/* Content */}
      <div style={{ paddingLeft: 'var(--space-3)' }}>
        <div className="stat-card__label">{label}</div>
        <div className="stat-card__value">{value}</div>
        {subtext && <div className="stat-card__subtext">{subtext}</div>}
      </div>
    </div>
  );
};
