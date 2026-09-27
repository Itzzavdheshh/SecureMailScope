"""
Application settings — loaded from environment variables / .env file.
Uses Pydantic BaseSettings for typed, validated configuration.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application ─────────────────────────────────────────────────────────
    app_name: str = "SecureMailScope"
    version: str = "0.1.0"
    environment: str = Field(default="development", alias="ENVIRONMENT")

    # ─── Server ──────────────────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    reload: bool = Field(default=True, alias="RELOAD")

    # ─── CORS ────────────────────────────────────────────────────────────────
    cors_origins: List[str] = Field(
        default=[
            "http://localhost:5173",   # Vite dev server
            "http://localhost:3000",   # Alternative dev
            "http://localhost:4173",   # Vite preview
        ],
        alias="CORS_ORIGINS",
    )

    # ─── Database ────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./securemailscope.db",
        alias="DATABASE_URL",
    )

    # ─── File storage ────────────────────────────────────────────────────────
    upload_dir: str = Field(default="./uploads", alias="UPLOAD_DIR")
    max_upload_size_mb: int = Field(default=200, alias="MAX_UPLOAD_SIZE_MB")

    # ─── Analysis ────────────────────────────────────────────────────────────
    rules_dir: str = Field(default="../rules", alias="RULES_DIR")
    analysis_timeout_seconds: int = Field(default=300, alias="ANALYSIS_TIMEOUT_SECONDS")

    # ─── Logging ─────────────────────────────────────────────────────────────
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")  # "json" | "console"


# Module-level singleton — imported everywhere as `from app.config import settings`
settings = Settings()
