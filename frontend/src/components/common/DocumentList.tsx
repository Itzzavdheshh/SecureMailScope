import React from 'react';
import { FileCode, FileText, FileSpreadsheet, Download, ExternalLink } from 'lucide-react';

interface ReportDoc {
  id: string;
  type: string;
  format: 'JSON' | 'HTML' | 'PDF';
  description: string;
  onView: () => void;
  onDownload: () => void;
}

interface DocumentListProps {
  documents: ReportDoc[];
}

export const DocumentList: React.FC<DocumentListProps> = ({ documents }) => {
  const getIcon = (format: string) => {
    switch (format) {
      case 'JSON':
        return <FileCode size={18} color="var(--color-blue-600)" />;
      case 'HTML':
        return <FileText size={18} color="var(--color-blue-600)" />;
      case 'PDF':
        return <FileSpreadsheet size={18} color="var(--color-critical)" />;
      default:
        return <FileText size={18} />;
    }
  };

  return (
    <div className="master-pane">
      <div
        style={{
          padding: '10px 14px',
          background: 'var(--color-bg-primary)',
          borderBottom: '1px solid var(--color-border)',
          fontSize: '11px',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          color: 'var(--color-text-muted)',
        }}
      >
        AVAILABLE FORENSIC REPORT ARTIFACTS
      </div>

      <table className="dense-table document-list__table">
        <thead>
          <tr>
            <th style={{ width: '40px' }}></th>
            <th>REPORT TYPE</th>
            <th>FORMAT</th>
            <th>DESCRIPTION</th>
            <th style={{ textAlign: 'right' }}>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {documents.map((doc) => (
            <tr key={doc.id}>
              <td>{getIcon(doc.format)}</td>
              <td style={{ fontWeight: 600 }}>{doc.type}</td>
              <td>
                <span className="badge badge--info" style={{ fontSize: '10px' }}>
                  {doc.format}
                </span>
              </td>
              <td style={{ color: 'var(--color-text-secondary)' }}>
                <span className="document-list__description" title={doc.description}>{doc.description}</span>
              </td>
              <td style={{ textAlign: 'right' }}>
                <div style={{ display: 'inline-flex', gap: '6px' }}>
                  <button
                    type="button"
                    className="btn btn--secondary"
                    style={{ padding: '3px 8px', fontSize: '11px', gap: '4px' }}
                    onClick={doc.onView}
                  >
                    <ExternalLink size={12} />
                    <span>Open</span>
                  </button>
                  <button
                    type="button"
                    className="btn btn--primary"
                    style={{ padding: '3px 8px', fontSize: '11px', gap: '4px' }}
                    onClick={doc.onDownload}
                  >
                    <Download size={12} />
                    <span>Download</span>
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
