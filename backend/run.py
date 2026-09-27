"""
Uvicorn entrypoint — used for local development.
Run with:  python run.py
Or:        uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

import uvicorn
from app.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_config=None,   # We manage logging via structlog
        access_log=False,  # Suppress uvicorn access log (structlog handles it)
    )
