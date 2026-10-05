import React from 'react';
import { FileText, CheckCircle2 } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { reportsApi } from '../api/services';
import { apiClient } from '../api/client';
import { EmptyState } from '../components/common/StateViews';
import { DocumentList } from '../components/common/DocumentList';
import { Badge, RiskBandBadge } from '../components/common/Badge';

export const ReportsPage: React.FC = () => {
  const { activeJob, activeCapture } = useWorkspace();

  if (!activeJob || activeJob.status !== 'COMPLETED') {
    return (
      <div className="workspace-page">
        <EmptyState
          title={activeJob?.status === 'FAILED' ? 'Analysis Failed' : 'No Completed Job Report Context'}
          subtitle={activeJob?.status === 'FAILED'
            ? activeJob.error_message || 'This analysis did not complete; no report or risk result is available.'
            : 'Run an analysis from Intake & PCAP and wait for it to complete before generating forensic reports.'}
          icon={<FileText size={36} />}
        />
      </div>
    );
  }

  const hasSessions = (activeJob.total_sessions ?? 0) > 0;

  const jsonUrl = reportsApi.getJobReportUrl(activeJob.id, 'json');
  const htmlUrl = reportsApi.getJobReportUrl(activeJob.id, 'html');
  const pdfUrl = reportsApi.getJobReportUrl(activeJob.id, 'pdf');

  const openReport = async (url: string) => {
    const reportWindow = window.open('about:blank', '_blank');
    if (!reportWindow) return;
    reportWindow.opener = null;

    try {
      const response = await apiClient.get<Blob>(url, { responseType: 'blob' });
      const objectUrl = URL.createObjectURL(response.data);
      reportWindow.location.href = objectUrl;
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
    } catch {
      reportWindow.close();
      window.alert('Unable to open this report. Please try again.');
    }
  };

  const downloadReport = async (url: string, format: 'json' | 'html' | 'pdf') => {
    try {
      const response = await apiClient.get<Blob>(url, { responseType: 'blob' });
      const objectUrl = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = `securemailscope-report-${activeJob.id.slice(0, 8)}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
    } catch {
      window.alert('Unable to download this report. Please try again.');
    }
  };

  const documents = [
    {
      id: 'doc-json',
      type: 'Structured Investigation Data Graph',
      format: 'JSON' as const,
      description: 'Machine-readable JSON data tree containing complete session, finding, and packet evidence fields.',
      onView: () => void openReport(jsonUrl),
      onDownload: () => void downloadReport(jsonUrl, 'json'),
    },
    {
      id: 'doc-html',
      type: 'Standalone Forensic Analysis Report',
      format: 'HTML' as const,
      description: 'Self-contained HTML report document with executive summary, tables, and evidence lineage.',
      onView: () => void openReport(htmlUrl),
      onDownload: () => void downloadReport(htmlUrl, 'html'),
    },
    {
      id: 'doc-pdf',
      type: 'Forensic Analysis Report',
      format: 'PDF' as const,
      description: 'Printable PDF report containing analysis results, findings, evidence references, timeline events, and investigation limitations.',
      onView: () => void openReport(pdfUrl),
      onDownload: () => void downloadReport(pdfUrl, 'pdf'),
    },
  ];

  return (
    <div className="workspace-page-scrollable">
      {/* Investigation Context Card */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Investigation Context & Report Parameters</span>
          {hasSessions ? (
            <RiskBandBadge band={activeJob.risk_band} />
          ) : (
            <Badge variant="neutral">INSUFFICIENT EVIDENCE</Badge>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', fontSize: '12px' }}>
          <div>
            <span style={{ color: 'var(--color-text-muted)', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>
              CAPTURE FILENAME
            </span>
            <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-blue-700)', marginTop: '2px' }}>
              {activeCapture?.filename || 'Active Capture'}
            </div>
          </div>

          <div>
            <span style={{ color: 'var(--color-text-muted)', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>
              ANALYSIS JOB ID
            </span>
            <div className="mono" style={{ marginTop: '2px' }}>
              {activeJob.id.substring(0, 16)}...
            </div>
          </div>

          <div>
            <span style={{ color: 'var(--color-text-muted)', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>
              RISK SCORE
            </span>
            <div className="mono" style={{ fontWeight: 700, color: 'var(--color-accent)', marginTop: '2px' }}>
              {activeJob.overall_risk_score !== null && activeJob.overall_risk_score !== undefined
                ? activeJob.overall_risk_score.toFixed(1)
                : '0.0'}{' '}
              / 100
            </div>
          </div>

          <div>
            <span style={{ color: 'var(--color-text-muted)', fontSize: '10px', textTransform: 'uppercase', fontWeight: 600 }}>
              COMPLETED TIMESTAMP
            </span>
            <div className="mono" style={{ marginTop: '2px' }}>
              {activeJob.completed_at ? new Date(activeJob.completed_at).toLocaleString() : 'In Progress'}
            </div>
          </div>
        </div>
      </div>

      {/* Available Reports Document List */}
      <DocumentList documents={documents} />

      {/* Report Content Disclosures & Integrity Checklist */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Report Content & Integrity Disclosures</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px', fontSize: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={16} color="var(--color-success)" />
            <span>Deterministic Rule Engine Evaluation</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={16} color="var(--color-success)" />
            <span>X.509 Certificate Chain Lineage</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={16} color="var(--color-success)" />
            <span>STARTTLS Negotiation Transcript</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={16} color="var(--color-success)" />
            <span>Cryptographic Baseline Drift Analysis</span>
          </div>
        </div>
      </div>
    </div>
  );
};
