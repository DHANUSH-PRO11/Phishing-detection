"""
Database Engine and Session Management.

Provides thread-safe SQLAlchemy engine and session management.
Defaults to SQLite for local zero-config development, but supports
PostgreSQL via the DATABASE_URL environment variable.
"""

from __future__ import annotations
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.app.core.config import settings

# Ensure SQLite directory exists if local file path
if settings.DATABASE_URL.startswith("sqlite"):
    # Extract path from sqlite:///./path/to/db.db
    db_path_str = settings.DATABASE_URL.replace("sqlite:///", "")
    db_path = Path(db_path_str).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

connect_args: dict[str, Any] = {}
engine_kwargs: dict[str, Any] = {
    "echo": settings.DEBUG,
    "pool_pre_ping": True,
}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    engine_kwargs["connect_args"] = connect_args
    if not settings.DATABASE_URL.endswith(":memory:"):
        from sqlalchemy.pool import QueuePool
        engine_kwargs["poolclass"] = QueuePool
        engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
        engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
        engine_kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT
else:
    # PostgreSQL / MySQL
    engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
    engine_kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT
    engine_kwargs["pool_recycle"] = 1800

engine = create_engine(
    settings.DATABASE_URL,
    **engine_kwargs
)

# Enable foreign keys for SQLite
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a clean database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates all database tables defined in Base metadata."""
    Base.metadata.create_all(bind=engine)
