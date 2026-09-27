"""
SecureMailScope Backend
FastAPI application entry point.

Phase 0: Minimal scaffold with health endpoint.
Analysis pipeline, DB, and full API surface are introduced in Phase 1+.
"""

import time
import sys
import warnings

# Suppress scapy libpcap warning on Windows (file reading works fine without it)
warnings.filterwarnings("ignore", message=".*No libpcap provider.*")
# Suppress FFDH deprecation from scapy's DH groups module
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from app.config import settings
from app.logging_config import configure_logging

# Configure structured logging before anything else
configure_logging()
log = structlog.get_logger(__name__)

# ─── Application factory ──────────────────────────────────────────────────────

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "securemailscope_startup",
        version="0.1.0",
        environment=settings.environment,
        python=sys.version,
    )
    yield
    log.info("securemailscope_shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecureMailScope API",
        description=(
            "AI-Assisted Cryptographic Security Posture Assessment "
            "for Secure Email Communications. "
            "SIH 2026 — Problem Statement 26159 — NTRO."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ─── CORS ────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ─── Routes ──────────────────────────────────────────────────────────────
    from app.api.health import router as health_router
    from app.api.captures import router as captures_router
    from app.api.jobs import router as jobs_router
    from app.api.v1 import v1_router

    app.include_router(health_router, prefix="/api")
    app.include_router(captures_router, prefix="/api")
    app.include_router(jobs_router, prefix="/api")
    app.include_router(v1_router, prefix="/api")

    return app




app = create_app()
