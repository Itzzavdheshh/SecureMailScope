import React from 'react';
import { FileCode, FileSpreadsheet, FileText, Download, ExternalLink } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { reportsApi } from '../api/services';
import { EmptyState } from '../components/common/StateViews';

export const ReportsPage: React.FC = () => {
  const { activeJob, activeCapture } = useWorkspace();

  if (!activeJob) {
    return (
      <EmptyState
        title="No Active Job Report Context"
        subtitle="Please select or run an analysis job to generate forensic investigation reports."
        icon={<FileText size={40} />}
      />
    );
  }

  const jsonUrl = reportsApi.getJobReportUrl(activeJob.id, 'json');
  const htmlUrl = reportsApi.getJobReportUrl(activeJob.id, 'html');
  const pdfUrl = reportsApi.getJobReportUrl(activeJob.id, 'pdf');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '900px', margin: '0 auto' }}>
      <div>
        <h2>Forensic Investigation Reports</h2>
        <p>Export deterministic forensic investigation reports generated directly by backend Phase 7 Report Engine.</p>
      </div>

      <div className="card" style={{ padding: '24px' }}>
        <h3 style={{ marginBottom: '8px' }}>Analysis Context Metadata</h3>
        <div className="grid-content-2" style={{ gap: '12px', fontSize: '0.875rem' }}>
          <div>
            <span style={{ color: 'var(--color-text-secondary)' }}>Capture Filename:</span><br />
            <strong>{activeCapture?.filename}</strong>
          </div>
          <div>
            <span style={{ color: 'var(--color-text-secondary)' }}>Analysis Job ID:</span><br />
            <span className="mono">{activeJob.id}</span>
          </div>
          <div>
            <span style={{ color: 'var(--color-text-secondary)' }}>Overall Posture Score:</span><br />
            <span className="mono" style={{ fontWeight: 700, color: 'var(--color-accent)' }}>
              {activeJob.overall_risk_score !== null && activeJob.overall_risk_score !== undefined
                ? activeJob.overall_risk_score.toFixed(1)
                : 'N/A'}{' '}
              ({activeJob.risk_band || 'SECURE'})
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--color-text-secondary)' }}>Completed At:</span><br />
            <span className="mono">
              {activeJob.completed_at ? new Date(activeJob.completed_at).toLocaleString() : 'In Progress'}
            </span>
          </div>
        </div>
      </div>

      {/* Format Options Grid */}
      <div className="grid-content-3" style={{ gap: '16px' }}>
        {/* JSON Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-accent)', marginBottom: '8px' }}>
              <FileCode size={24} />
              <h3 style={{ margin: 0 }}>JSON Data Graph</h3>
            </div>
            <p style={{ fontSize: '0.85rem' }}>
              Machine-readable structured JSON graph containing complete domain object trees, sessions, findings, and evidence fields.
            </p>
          </div>

          <a href={jsonUrl} target="_blank" rel="noreferrer" className="btn btn--secondary" style={{ justifyContent: 'center' }}>
            <ExternalLink size={16} /> Open Raw JSON
          </a>
        </div>

        {/* HTML Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-info)', marginBottom: '8px' }}>
              <FileSpreadsheet size={24} />
              <h3 style={{ margin: 0 }}>Dark HTML Report</h3>
            </div>
            <p style={{ fontSize: '0.85rem' }}>
              Standalone dark-themed HTML report, self-contained with no external CSS/script dependencies for offline sharing.
            </p>
          </div>

          <a href={htmlUrl} target="_blank" rel="noreferrer" className="btn btn--primary" style={{ justifyContent: 'center' }}>
            <ExternalLink size={16} /> View Dark HTML
          </a>
        </div>

        {/* PDF Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-high)', marginBottom: '8px' }}>
              <FileText size={24} />
              <h3 style={{ margin: 0 }}>ReportLab PDF</h3>
            </div>
            <p style={{ fontSize: '0.85rem' }}>
              Printable PDF report document formatted with executive posture summary, rule findings table, session index, and disclosures.
            </p>
          </div>

          <a href={pdfUrl} className="btn btn--secondary" style={{ justifyContent: 'center', color: 'var(--color-high)', borderColor: 'var(--color-high)' }}>
            <Download size={16} /> Download PDF
          </a>
        </div>
      </div>
    </div>
  );
};
