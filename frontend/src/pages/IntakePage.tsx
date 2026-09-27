import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, FileCheck, Play, CheckCircle, AlertTriangle, Loader2 } from 'lucide-react';
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
    } finally {
      setIsUploading(false);
    }
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
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: '24px' }}>
        <h2>Network Packet Capture Intake</h2>
        <p>Ingest PCAP or PCAPNG packet capture files for deterministic cryptographic security analysis.</p>
      </div>

      <div className="card" style={{ padding: '32px', textAlign: 'center' }}>
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
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '40px 20px',
            border: '2px dashed var(--color-border-strong)',
            borderRadius: '12px',
            cursor: 'pointer',
            backgroundColor: 'var(--color-bg-primary)',
            transition: 'border-color var(--transition-fast)',
          }}
        >
          <UploadCloud size={48} style={{ color: 'var(--color-accent)', marginBottom: '16px' }} />
          <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--color-text)', marginBottom: '8px' }}>
            {selectedFile ? selectedFile.name : 'Select or Drop Network Capture File (.pcap / .pcapng)'}
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>
            {selectedFile
              ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`
              : 'Maximum intake limit: 100 MB per capture file'}
          </div>
        </label>

        {selectedFile && !uploadResult && (
          <button
            onClick={handleUpload}
            disabled={isUploading}
            className="btn btn--primary"
            style={{ marginTop: '24px', padding: '10px 24px' }}
          >
            {isUploading ? (
              <>
                <Loader2 size={18} className="spinner" style={{ animation: 'spin 1s linear infinite' }} />
                Ingesting and Validating Capture...
              </>
            ) : (
              <>
                <FileCheck size={18} /> Ingest Capture File
              </>
            )}
          </button>
        )}
      </div>

      {errorMsg && (
        <div className="error-banner" style={{ marginTop: '20px' }}>
          <AlertTriangle size={20} />
          <div>{errorMsg}</div>
        </div>
      )}

      {uploadResult && (
        <div className="card" style={{ marginTop: '24px', borderLeft: '4px solid var(--color-success)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <CheckCircle size={24} style={{ color: 'var(--color-success)' }} />
            <div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600 }}>Capture Ingested & Validated</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>{uploadResult.message}</div>
            </div>
          </div>

          <div className="grid-content-2" style={{ gap: '12px', fontSize: '0.875rem' }}>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Filename:</span>{' '}
              <strong style={{ color: 'var(--color-text)' }}>{uploadResult.filename}</strong>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>File Size:</span>{' '}
              <span className="mono">{uploadResult.file_size_bytes.toLocaleString()} bytes</span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Total Packets:</span>{' '}
              <span className="mono">{uploadResult.total_packets}</span>
            </div>
            <div>
              <span style={{ color: 'var(--color-text-secondary)' }}>Analysis Job ID:</span>{' '}
              <span className="mono">{uploadResult.job_id}</span>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <span style={{ color: 'var(--color-text-secondary)' }}>SHA-256 Hash:</span><br />
              <span className="hash">{uploadResult.sha256_hash}</span>
            </div>
          </div>

          <button
            onClick={handleStartAnalysis}
            disabled={isStartingJob}
            className="btn btn--primary"
            style={{ marginTop: '20px', width: '100%', justifyContent: 'center', padding: '12px' }}
          >
            {isStartingJob ? (
              <>
                <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                Executing Pipeline (TCP, TLS, X.509, STARTTLS, Rules, Drift)...
              </>
            ) : (
              <>
                <Play size={18} /> Execute Forensic Pipeline & Open Overview
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};
