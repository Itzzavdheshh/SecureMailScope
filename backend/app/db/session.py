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

# ─── Declarative Base ─────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """Base class for all SQLAlchemy 2.x domain models."""
    pass


# ─── Async Engine ─────────────────────────────────────────────────────────────

# SQLite async URL from settings
engine = create_async_engine(
    settings.database_url,
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


async def init_db() -> None:
    """Initialize database tables (used for testing or cold start)."""
    # Import all models to ensure metadata registration
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
