import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, FileCheck, Play, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { useWorkspace } from '../context/WorkspaceContext';
import { capturesApi, jobsApi } from '../api/services';
import type { CaptureUploadResponse } from '../types/api';

export const IntakePage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<CaptureUploadResponse | null>(null);
  const [isStartingJob, setIsStartingJob] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const { refreshCaptures, setActiveCapture, setActiveJob } = useWorkspace();
  const navigate = useNavigate();

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setErrorMsg(null);
      setUploadResult(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setErrorMsg(null);

    try {
      const res = await capturesApi.upload(selectedFile);
      setUploadResult(res);
      await refreshCaptures();
      setActiveCapture(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to upload packet capture file.');
    } Promise.resolve().finally(() => {
      setIsUploading(false);
    });
  };

  const handleStartAnalysis = async () => {
    if (!uploadResult) return;
    setIsStartingJob(true);
    setErrorMsg(null);

    try {
      const res = await jobsApi.start(uploadResult.job_id);
      setActiveJob(res.job);
      navigate('/');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to start analysis pipeline.');
    } finally {
      setIsStartingJob(false);
    }
  };

  return (
    <div className="workspace-page-scrollable" style={{ maxWidth: '900px', margin: '0 auto' }}>
      {/* STEP 1: SELECT FILE */}
      <div className="card">
        <div className="card-header" style={{ flexWrap: 'wrap', gap: '8px' }}>
          <span className="card-title">STEP 1 — SELECT NETWORK CAPTURE FILE</span>
          <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 500 }}>
            SUPPORTED FORMATS: .PCAP · .PCAPNG
          </span>
        </div>

        <input
          type="file"
          id="pcap-upload-input"
          accept=".pcap,.pcapng"
          onChange={handleFileChange}
          style={{ display: 'none' }}
        />

        <label
          htmlFor="pcap-upload-input"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
            padding: '16px 20px',
            border: '2px dashed var(--color-border)',
            borderRadius: 'var(--radius-md)',
            cursor: 'pointer',
            backgroundColor: 'var(--color-bg-primary)',
          }}
        >
          <UploadCloud size={32} color="var(--color-blue-700)" />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text)' }}>
              {selectedFile ? selectedFile.name : 'Click to select or drop a PCAP file'}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
              {selectedFile
                ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`
                : 'Supports libpcap and pcapng formats up to 200 MB'}
            </div>
          </div>
          {selectedFile && !uploadResult && (
            <button
              type="button"
              onClick={(e) => {
                e.preventDefault();
                handleUpload();
              }}
              disabled={isUploading}
              className="btn btn--primary"
              style={{ fontSize: '12px', gap: '6px' }}
            >
              {isUploading ? (
                <>
                  <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
                  Uploading...
                </>
              ) : (
                <>
                  <FileCheck size={14} /> Ingest File
                </>
              )}
            </button>
          )}
        </label>
      </div>

      {errorMsg && (
        <div className="error-banner">
          <AlertTriangle size={18} />
          <div>{errorMsg}</div>
        </div>
      )}

      {/* STEP 2: CAPTURE VALIDATION */}
      {uploadResult && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">STEP 2 — CAPTURE VALIDATION METADATA</span>
            <span className="badge badge--secure" style={{ fontSize: '10px' }}>
              VALIDATED
            </span>
          </div>

          <table className="dense-table">
            <tbody>
              <tr>
                <td style={{ width: '180px', fontWeight: 600, color: 'var(--color-text-muted)' }}>FILENAME</td>
                <td className="mono" style={{ fontWeight: 700, color: 'var(--color-blue-700)' }}>
                  {uploadResult.filename}
                </td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--color-text-muted)' }}>FILE SIZE</td>
                <td className="mono">{uploadResult.file_size_bytes.toLocaleString()} bytes</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--color-text-muted)' }}>TOTAL PACKETS</td>
                <td className="mono">{uploadResult.total_packets} packets</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--color-text-muted)' }}>ANALYSIS JOB ID</td>
                <td className="mono">{uploadResult.job_id}</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--color-text-muted)' }}>SHA-256 HASH</td>
                <td className="hash">{uploadResult.sha256_hash}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {/* STEP 3: EXECUTE ANALYSIS PIPELINE */}
      {uploadResult && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">STEP 3 — EXECUTE ANALYSIS PIPELINE</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div className="pipeline-trace" style={{ justifyContent: 'space-between' }}>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>Ingest & Checksum</span>
              </div>
              <span className="pipeline-step-arrow">→</span>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>Session Assembly</span>
              </div>
              <span className="pipeline-step-arrow">→</span>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>TLS & X.509 Parse</span>
              </div>
              <span className="pipeline-step-arrow">→</span>
              <div className="pipeline-step completed">
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span>Rule Engine</span>
              </div>
            </div>

            <button
              type="button"
              onClick={handleStartAnalysis}
              disabled={isStartingJob}
              className="btn btn--primary"
              style={{ width: '100%', justifyContent: 'center', padding: '10px', fontSize: '13px', gap: '8px' }}
            >
              {isStartingJob ? (
                <>
                  <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
                  Executing Analysis Pipeline...
                </>
              ) : (
                <>
                  <Play size={16} /> Run Pipeline & Launch Investigation Workspace
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
