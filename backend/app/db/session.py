"""
Database engine, session factory, and dependency injection setup.
Configured for SQLite (aiosqlite) with foreign keys enabled, migration-ready for PostgreSQL.
"""

import sqlite3
from typing import AsyncGenerator
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


def normalize_database_url(database_url: str) -> str:
    """Use the async PostgreSQL driver for Render's generic Postgres URLs."""
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+asyncpg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return database_url

# ─── Declarative Base ─────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """Base class for all SQLAlchemy 2.x domain models."""
    pass


# ─── Async Engine ─────────────────────────────────────────────────────────────

# SQLite async URL from settings
engine = create_async_engine(
    normalize_database_url(settings.database_url),
    echo=settings.log_level.upper() == "DEBUG",
    future=True,
    # SQLite-specific connect args
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
)


# Enforce SQLite foreign key constraints on every connection
@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


# ─── Session Factory ──────────────────────────────────────────────────────────

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ─── Dependency Injection ─────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


from sqlalchemy import inspect, text

async def init_db() -> None:
    """Initialize database tables (used for testing or cold start)."""
    # Import all models to ensure metadata registration
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        def _migrate(sync_conn):
            inspector = inspect(sync_conn)
            if "infrastructure_identities" in inspector.get_table_names():
                columns = [c["name"] for c in inspector.get_columns("infrastructure_identities")]
                if "port" not in columns:
                    sync_conn.execute(text("ALTER TABLE infrastructure_identities ADD COLUMN port INTEGER"))
                if "protocol" not in columns:
                    sync_conn.execute(text("ALTER TABLE infrastructure_identities ADD COLUMN protocol VARCHAR(20)"))
                if "identity_key" not in columns:
                    sync_conn.execute(text("ALTER TABLE infrastructure_identities ADD COLUMN identity_key VARCHAR(64)"))
                if "active_profile_json" not in columns:
                    sync_conn.execute(text("ALTER TABLE infrastructure_identities ADD COLUMN active_profile_json TEXT"))

        await conn.run_sync(_migrate)

