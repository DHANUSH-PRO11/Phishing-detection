"""
Application Configuration and Environment Settings.

Loads configurations from environment variables or .env file using Pydantic Settings.
Enforces security parameters, CORS origin whitelisting, and database connectivity.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent  # .../backend
REPO_ROOT = BACKEND_DIR.parent


def _resolve_dir(sub_name: str) -> str:
    """Safely resolves subdirectories (artifacts, data, reports) relative to backend."""
    candidates = [
        BACKEND_DIR / sub_name,
        REPO_ROOT / "backend" / sub_name,
        Path(f"backend/{sub_name}"),
        Path(sub_name),
    ]
    for c in candidates:
        if c.exists():
            return str(c.resolve())
    return str((BACKEND_DIR / sub_name).resolve())


def _resolve_default_db_url() -> str:
    """Resolves default SQLite database URL to an absolute posix path."""
    db_file = Path(_resolve_dir("data")) / "phishing_detector.db"
    return f"sqlite:///{db_file.as_posix()}"


class Settings(BaseSettings):
    """Core application settings."""

    APP_NAME: str = Field(default="Phishing URL Detection System")
    APP_ENV: str = Field(default="development")
    DEBUG: bool = Field(default=False)
    API_PREFIX: str = Field(default="/api")

    # Security and CORS
    ALLOWED_ORIGINS: Union[List[str], str] = Field(
        default=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]
    )
    RATE_LIMIT_PER_MINUTE: int = Field(default=60)
    MAX_URL_LENGTH: int = Field(default=2048)

    # Persistence: SQLite default, swappable for PostgreSQL
    DATABASE_URL: str = Field(default_factory=_resolve_default_db_url)
    DB_POOL_SIZE: int = Field(default=20)
    DB_MAX_OVERFLOW: int = Field(default=30)
    DB_POOL_TIMEOUT: int = Field(default=30)

    # ML Artifacts and Reports
    MODEL_DIR: str = Field(default_factory=lambda: _resolve_dir("artifacts"))
    REPORTS_DIR: str = Field(default_factory=lambda: _resolve_dir("reports"))

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        if isinstance(v, str) and v.startswith("sqlite:///./backend/data/"):
            clean_name = v.replace("sqlite:///./backend/data/", "")
            resolved = Path(_resolve_dir("data")) / clean_name
            return f"sqlite:///{resolved.as_posix()}"
        elif isinstance(v, str) and v.startswith("sqlite:///backend/data/"):
            clean_name = v.replace("sqlite:///backend/data/", "")
            resolved = Path(_resolve_dir("data")) / clean_name
            return f"sqlite:///{resolved.as_posix()}"
        return v

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


# Global singleton instance
settings = Settings()
