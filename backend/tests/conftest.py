"""
pytest configuration and shared fixtures.
Phase 0: Minimal setup. Extended in Phase 1+ with DB fixtures.
"""

import pytest
import warnings
from httpx import AsyncClient, ASGITransport

# Suppress scapy warnings in test output
warnings.filterwarnings("ignore", message=".*No libpcap provider.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """Async test client for the FastAPI app."""
    from app.main import app
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
