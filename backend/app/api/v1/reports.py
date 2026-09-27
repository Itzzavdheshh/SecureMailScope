"""
API v1 Reports router.
Provides deterministic investigation report generation in JSON, HTML, and PDF formats.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models import AnalysisJob
from app.reports.report_generator import (
    build_report_data_graph,
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)

router = APIRouter()

SUPPORTED_FORMATS = {"json", "html", "pdf"}


@router.get(
    "/reports/{job_id}",
    summary="Get job investigation report (v1)",
    description="Generate a deterministic forensic investigation report for an AnalysisJob in JSON, HTML, or PDF format.",
)
async def get_job_report_v1(
    job_id: str,
    format: str = Query(default="json", description="Report format: 'json', 'html', or 'pdf'"),
    db: AsyncSession = Depends(get_db),
):
    fmt = format.lower().strip()
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid report format '{format}'. Supported formats are: json, html, pdf.",
        )

    data = await build_report_data_graph(db, job_id=job_id)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisJob with ID '{job_id}' not found.",
        )

    if fmt == "json":
        return Response(
            content=generate_json_report(data),
            media_type="application/json",
        )
    elif fmt == "html":
        return Response(
            content=generate_html_report(data),
            media_type="text/html",
        )
    elif fmt == "pdf":
        pdf_bytes = generate_pdf_report(data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="securemailscope_report_{job_id[:8]}.pdf"'
            },
        )


@router.get(
    "/captures/{capture_id}/report",
    summary="Get capture investigation report (v1)",
    description="Generate a deterministic forensic investigation report for a capture's latest analysis job in JSON, HTML, or PDF format.",
)
async def get_capture_report_v1(
    capture_id: str,
    format: str = Query(default="json", description="Report format: 'json', 'html', or 'pdf'"),
    db: AsyncSession = Depends(get_db),
):
    fmt = format.lower().strip()
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid report format '{format}'. Supported formats are: json, html, pdf.",
        )

    stmt = (
        select(AnalysisJob)
        .where(AnalysisJob.capture_id == capture_id)
        .order_by(AnalysisJob.created_at.desc())
    )
    res = await db.execute(stmt)
    job = res.scalar_one_or_none()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No analysis job found for capture ID '{capture_id}'.",
        )

    data = await build_report_data_graph(db, job_id=job.id)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report data graph could not be generated for capture ID '{capture_id}'.",
        )

    if fmt == "json":
        return Response(
            content=generate_json_report(data),
            media_type="application/json",
        )
    elif fmt == "html":
        return Response(
            content=generate_html_report(data),
            media_type="text/html",
        )
    elif fmt == "pdf":
        pdf_bytes = generate_pdf_report(data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="securemailscope_report_{capture_id[:8]}.pdf"'
            },
        )
