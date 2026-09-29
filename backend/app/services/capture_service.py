"""
Capture Ingestion Service.
Securely handles PCAP/PCAPNG file uploads: validation, streaming hash calculation,
safe storage, metadata extraction, duplicate detection, and AnalysisJob creation.
"""

import hashlib
import os
import uuid
from pathlib import Path
from typing import Optional, Tuple
from fastapi import HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Capture, AnalysisJob, JobStatus
from app.utils.pcap_inspector import detect_pcap_format, inspect_pcap_file


ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def get_upload_directory() -> Path:
    """Ensure upload directory exists and return resolved Path object."""
    upload_path = Path(settings.upload_dir).resolve()
    upload_path.mkdir(parents=True, exist_ok=True)
    return upload_path


def sanitize_filename(filename: Optional[str]) -> str:
    """Sanitize uploaded filename against path traversal attacks."""
    if not filename:
        return "unnamed_capture.pcap"
    # Extract basename only to prevent path traversal
    safe_name = Path(filename).name
    # Strip dangerous characters
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._- ")
    return safe_name.strip() or "unnamed_capture.pcap"


async def ingest_pcap_upload(
    file: UploadFile, db: AsyncSession
) -> Tuple[Capture, AnalysisJob]:
    """
    Ingest, validate, hash, store, and create database records for a PCAP upload.

    Raises:
        HTTPException 400: Invalid file extension or corrupted magic bytes.
        HTTPException 413: Upload size exceeds maximum limit.
        HTTPException 409: Duplicate file uploaded (matching SHA-256 hash).
    """
    original_filename = sanitize_filename(file.filename)
    ext = Path(original_filename).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only .pcap and .pcapng files are supported.",
        )

    upload_dir = get_upload_directory()
    tmp_dir = upload_dir / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    temp_file_id = str(uuid.uuid4())
    temp_file_path = tmp_dir / f"upload_{temp_file_id}.tmp"

    sha256_hasher = hashlib.sha256()
    total_bytes = 0
    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024

    header_bytes = bytearray()
    chunk_size = 64 * 1024  # 64 KB streaming chunks

    try:
        with open(temp_file_path, "wb") as f_out:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > max_size_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File size exceeds maximum allowed upload limit of {settings.max_upload_size_mb} MB.",
                    )

                if len(header_bytes) < 16:
                    header_bytes.extend(chunk[: 16 - len(header_bytes)])

                sha256_hasher.update(chunk)
                f_out.write(chunk)

        # Validate magic bytes
        fmt = detect_pcap_format(bytes(header_bytes))
        if fmt == "unknown":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file format: Unrecognized PCAP magic bytes signature.",
            )

        sha256_hash = sha256_hasher.hexdigest()

        # Check duplicate hash in DB
        stmt = select(Capture).where(Capture.sha256_hash == sha256_hash)
        res = await db.execute(stmt)
        existing_capture = res.scalar_one_or_none()

        if existing_capture is not None:
            # Clean up temp file
            if temp_file_path.exists():
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass

            # Create a new AnalysisJob for the existing capture so it can be analyzed
            job = AnalysisJob(
                capture_id=existing_capture.id,
                status=JobStatus.PENDING,
                total_sessions=0,
                total_findings=0,
            )
            db.add(job)
            await db.commit()
            await db.refresh(job)

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "Duplicate capture file already exists.",
                    "existing_capture_id": existing_capture.id,
                    "id": existing_capture.id,
                    "filename": existing_capture.filename,
                    "file_path": existing_capture.file_path,
                    "file_size_bytes": existing_capture.file_size_bytes,
                    "sha256_hash": sha256_hash,
                    "total_packets": existing_capture.total_packets,
                    "job_id": job.id,
                    "job_status": job.status.value if hasattr(job.status, "value") else str(job.status),
                },
            )

        # Generate safe permanent storage name
        target_ext = ".pcapng" if fmt == "pcapng" else ".pcap"
        storage_filename = f"{uuid.uuid4().hex}{target_ext}"
        permanent_path = upload_dir / storage_filename

        # Prevent path traversal verification
        if not permanent_path.resolve().is_relative_to(upload_dir.resolve()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path traversal attempt detected in target path.",
            )

        # Move temp file to permanent location
        os.replace(temp_file_path, permanent_path)

        # Extract lightweight metadata
        metadata = inspect_pcap_file(permanent_path)

        # Create Capture record
        capture = Capture(
            filename=original_filename,
            file_path=str(permanent_path),
            file_size_bytes=total_bytes,
            sha256_hash=sha256_hash,
            total_packets=metadata.total_packets,
            capture_start_time=metadata.capture_start_time,
            capture_end_time=metadata.capture_end_time,
            status="UPLOADED",
        )
        db.add(capture)
        await db.flush()  # Generate capture.id

        # Create initial AnalysisJob record (ready for Phase 3 analysis)
        job = AnalysisJob(
            capture_id=capture.id,
            status=JobStatus.PENDING,
            total_sessions=0,
            total_findings=0,
        )
        db.add(job)

        await db.commit()
        await db.refresh(capture)
        await db.refresh(job)

        return capture, job

    except Exception:
        # Guarantee cleanup of incomplete or rejected upload files
        if temp_file_path.exists():
            try:
                os.remove(temp_file_path)
            except OSError:
                pass
        raise
