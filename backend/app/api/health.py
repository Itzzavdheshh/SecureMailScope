"""
Health check router.
Provides liveness and readiness endpoints for monitoring and Docker health checks.
"""

import time
import sys
import platform
from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from app.config import settings

router = APIRouter(tags=["health"])

_startup_time = time.time()


class ComponentStatus(BaseModel):
    status: str           # "ok" | "degraded" | "unavailable"
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str                              # "ok" | "degraded"
    version: str
    environment: str
    uptime_seconds: float
    timestamp: str
    python_version: str
    platform: str
    components: dict[str, ComponentStatus]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description=(
        "Returns 200 when the application is running. "
        "Checks core component availability without performing analysis."
    ),
)
async def health_check() -> HealthResponse:
    """
    Liveness endpoint. Called by Docker, load balancers, and the frontend
    to confirm the API is reachable.
    """
    components: dict[str, ComponentStatus] = {}

    # Check: can we import the core analysis libraries?
    try:
        import dpkt  # noqa: F401
        components["dpkt"] = ComponentStatus(status="ok", detail=dpkt.__version__ if hasattr(dpkt, '__version__') else "installed")
    except ImportError as e:
        components["dpkt"] = ComponentStatus(status="unavailable", detail=str(e))

    try:
        import scapy  # noqa: F401
        import scapy.all  # noqa: F401
        components["scapy"] = ComponentStatus(status="ok", detail=scapy.__version__)
    except ImportError as e:
        components["scapy"] = ComponentStatus(status="unavailable", detail=str(e))

    try:
        from cryptography import x509  # noqa: F401
        import cryptography
        components["cryptography"] = ComponentStatus(status="ok", detail=cryptography.__version__)
    except ImportError as e:
        components["cryptography"] = ComponentStatus(status="unavailable", detail=str(e))

    try:
        import sklearn  # noqa: F401
        components["scikit-learn"] = ComponentStatus(status="ok", detail=sklearn.__version__)
    except ImportError as e:
        components["scikit-learn"] = ComponentStatus(status="unavailable", detail=str(e))

    try:
        import yaml  # noqa: F401
        components["pyyaml"] = ComponentStatus(status="ok")
    except ImportError as e:
        components["pyyaml"] = ComponentStatus(status="unavailable", detail=str(e))

    # Database check deferred to Phase 1 (DB not yet initialized)
    components["database"] = ComponentStatus(
        status="not_initialized",
        detail="Database initialization is part of Phase 1",
    )

    overall = "ok"
    critical = {"dpkt", "scapy", "cryptography"}
    for name in critical:
        if components.get(name, ComponentStatus(status="unavailable")).status != "ok":
            overall = "degraded"
            break

    return HealthResponse(
        status=overall,
        version=settings.version,
        environment=settings.environment,
        uptime_seconds=round(time.time() - _startup_time, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
        python_version=sys.version,
        platform=platform.platform(),
        components=components,
    )


@router.get(
    "/health/ready",
    summary="Readiness check",
    description="Returns 200 when the application is ready to serve requests.",
)
async def readiness_check() -> dict:
    """
    Readiness probe. Returns 503 if critical components are missing.
    Extended in Phase 1 to also verify DB connectivity.
    """
    missing = []
    for lib in ("dpkt", "scapy", "cryptography"):
        try:
            __import__(lib)
        except ImportError:
            missing.append(lib)

    if missing:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=503,
            detail=f"Critical libraries missing: {missing}",
        )

    return {"status": "ready", "version": settings.version}
