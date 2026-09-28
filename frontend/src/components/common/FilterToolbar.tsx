import { Filter, RotateCcw } from 'lucide-react';

export interface FilterOption {
  key: string;
  label: string;
  value: string;
  options: { label: string; value: string }[];
  onChange: (val: string) => void;
}

interface FilterToolbarProps {
  searchValue?: string;
  onSearchChange?: (val: string) => void;
  searchPlaceholder?: string;
  filters?: FilterOption[];
  onReset?: () => void;
  actionButton?: React.ReactNode;
}

export const FilterToolbar: React.FC<FilterToolbarProps> = ({
  searchValue = '',
  onSearchChange,
  searchPlaceholder = 'Filter records...',
  filters = [],
  onReset,
  actionButton,
}) => {
  return (
    <div className="filter-toolbar">
      <div className="filter-toolbar-group">
        <Filter size={14} color="var(--color-text-muted)" />

        {onSearchChange && (
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <input
              type="text"
              className="filter-search"
              placeholder={searchPlaceholder}
              value={searchValue}
              onChange={(e) => onSearchChange(e.target.value)}
            />
            {searchValue && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                style={{
                  position: 'absolute',
                  right: '6px',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--color-text-muted)',
                  fontSize: '11px',
                }}
              >
                ✕
              </button>
            )}
          </div>
        )}

        {filters.map((f) => (
          <select
            key={f.key}
            className="filter-select"
            value={f.value}
            onChange={(e) => f.onChange(e.target.value)}
          >
            <option value="">{f.label}: All</option>
            {f.options.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        ))}

        {onReset && (
          <button
            type="button"
            className="btn btn--ghost"
            style={{ padding: '3px 8px', fontSize: '11px', gap: '4px' }}
            onClick={onReset}
            title="Reset all filters"
          >
            <RotateCcw size={12} />
            <span>Reset</span>
          </button>
        )}
      </div>

      {actionButton && <div>{actionButton}</div>}
    </div>
  );
};
