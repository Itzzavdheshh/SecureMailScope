import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  page: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (newPage: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
}) => {
  if (totalPages <= 1) return null;

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, totalItems);

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 16px',
        borderTop: '1px solid var(--color-border)',
        fontSize: '0.875rem',
        color: 'var(--color-text-secondary)',
      }}
    >
      <div>
        Showing <span className="mono" style={{ color: 'var(--color-text)' }}>{start}</span> to{' '}
        <span className="mono" style={{ color: 'var(--color-text)' }}>{end}</span> of{' '}
        <span className="mono" style={{ color: 'var(--color-text)' }}>{totalItems}</span> records
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <button
          className="btn btn--ghost"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          style={{ padding: '4px 8px' }}
        >
          <ChevronLeft size={16} /> Previous
        </button>
        <span className="mono" style={{ fontSize: '0.8rem', padding: '0 8px' }}>
          Page {page} of {totalPages}
        </span>
        <button
          className="btn btn--ghost"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          style={{ padding: '4px 8px' }}
        >
          Next <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
};
