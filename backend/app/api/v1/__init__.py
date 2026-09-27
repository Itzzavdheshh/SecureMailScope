"""
API v1 Package Router.
Exports and mounts all version 1 REST resource routers.
"""

from fastapi import APIRouter

from app.api.v1.captures import router as captures_router
from app.api.v1.jobs import router as jobs_router
from app.api.v1.sessions import router as sessions_router
from app.api.v1.findings import router as findings_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.infrastructure import router as infra_router
from app.api.v1.drifts import router as drifts_router
from app.api.v1.timeline import router as timeline_router
from app.api.v1.risk import router as risk_router
from app.api.v1.reports import router as reports_router

v1_router = APIRouter(prefix="/v1")

v1_router.include_router(captures_router, prefix="/captures", tags=["v1-captures"])
v1_router.include_router(jobs_router, prefix="/jobs", tags=["v1-jobs"])
v1_router.include_router(sessions_router, prefix="/sessions", tags=["v1-sessions"])
v1_router.include_router(findings_router, prefix="/findings", tags=["v1-findings"])
v1_router.include_router(evidence_router, prefix="/evidence", tags=["v1-evidence"])
v1_router.include_router(infra_router, prefix="/infrastructure", tags=["v1-infrastructure"])
v1_router.include_router(drifts_router, prefix="/drifts", tags=["v1-drifts"])
v1_router.include_router(timeline_router, tags=["v1-timeline"])
v1_router.include_router(risk_router, tags=["v1-risk"])
v1_router.include_router(reports_router, tags=["v1-reports"])
