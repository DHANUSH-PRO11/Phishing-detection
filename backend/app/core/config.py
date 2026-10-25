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
    DATABASE_URL: str = Field(default="sqlite:///./backend/data/phishing_detector.db")

    # ML Artifacts and Reports
    MODEL_DIR: str = Field(default="backend/artifacts")
    REPORTS_DIR: str = Field(default="backend/reports")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


# Global singleton instance
settings = Settings()
