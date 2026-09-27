"""
Phase 0 health endpoint tests.
Verify the application starts and health check responds correctly.
"""

import pytest
from httpx import AsyncClient, ASGITransport


@pytest.mark.anyio
async def test_health_returns_200():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_health_response_structure():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "environment" in data
    assert "uptime_seconds" in data
    assert "components" in data
    assert data["version"] == "0.1.0"


@pytest.mark.anyio
async def test_health_components_present():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")
    components = response.json()["components"]
    assert "dpkt" in components
    assert "scapy" in components
    assert "cryptography" in components
    assert "scikit-learn" in components


@pytest.mark.anyio
async def test_readiness_returns_200():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


@pytest.mark.anyio
async def test_openapi_schema_accessible():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "SecureMailScope API"
