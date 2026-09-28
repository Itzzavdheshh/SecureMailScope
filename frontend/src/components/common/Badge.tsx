import React from 'react';
import type { Severity, RiskBand, StarttlsStatus } from '../../types/api';

interface BadgeProps {
  label?: string;
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'secure' | 'neutral';
  children?: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({ label, variant = 'info', children }) => {
  const content = label || children;
  return <span className={`badge badge--${variant}`}>{content}</span>;
};

export const SeverityBadge: React.FC<{ severity: Severity }> = ({ severity }) => {
  const variantMap: Record<Severity, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info',
  };
  return <Badge variant={variantMap[severity] || 'info'}>{severity}</Badge>;
};

export const RiskBandBadge: React.FC<{ band?: RiskBand | null }> = ({ band }) => {
  if (!band) return <Badge variant="neutral">UNKNOWN</Badge>;
  const variantMap: Record<RiskBand, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    SECURE: 'info',
  };
  return <Badge variant={variantMap[band] || 'info'}>{band}</Badge>;
};

export const StarttlsStateBadge: React.FC<{ state: StarttlsStatus }> = ({ state }) => {
  // Maps backend StarttlsStatus enum values to badge variants.
  // Backend enum (app/models/enums.py): NOT_OBSERVED | ADVERTISED | ATTEMPTED | ACCEPTED | REJECTED | ANOMALOUS
  switch (state) {
    case 'ACCEPTED':
      return <Badge variant="low">ACCEPTED</Badge>;
    case 'ADVERTISED':
    case 'ATTEMPTED':
      return <Badge variant="medium">{state}</Badge>;
    case 'REJECTED':
      return <Badge variant="critical">REJECTED</Badge>;
    case 'ANOMALOUS':
      return <Badge variant="high">ANOMALOUS</Badge>;
    case 'NOT_OBSERVED':
    default:
      return <Badge variant="info">NOT OBSERVED</Badge>;
  }
};
