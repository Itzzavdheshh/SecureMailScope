import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
async def test_health_endpoint():
    """Verify that GET /api/health returns HTTP 200 and healthy status."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ok", "healthy")
        assert "version" in data
        assert "timestamp" in data


def test_postgresql_urls_select_asyncpg_driver():
    from app.db.session import normalize_database_url

    assert normalize_database_url("postgres://user:pass@host/db") == "postgresql+asyncpg://user:pass@host/db"
    assert normalize_database_url("postgresql://user:pass@host/db") == "postgresql+asyncpg://user:pass@host/db"
    assert normalize_database_url("sqlite+aiosqlite:///local.db") == "sqlite+aiosqlite:///local.db"


@pytest.mark.asyncio
async def test_application_startup_initializes_sqlite_tables(tmp_path, monkeypatch):
    from sqlalchemy import inspect
    from app.db import session as db_session

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'startup.db'}")
    monkeypatch.setattr(db_session, "engine", engine)
    try:
        async with app.router.lifespan_context(app):
            async with engine.connect() as connection:
                tables = await connection.run_sync(lambda conn: inspect(conn).get_table_names())
            assert "captures" in tables
            assert "analysis_jobs" in tables
    finally:
        await engine.dispose()

