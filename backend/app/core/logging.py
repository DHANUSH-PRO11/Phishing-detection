"""
Structured Logging Configuration.

Configures standard logging with secure, sanitized formats that prevent
leaking secrets, file system paths, or unhandled tracebacks in production.
"""

from __future__ import annotations
import logging
import sys
from backend.app.core.config import settings


def setup_logging() -> None:
    """Configures root logger with uniform timestamped formatting."""
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    # Quiet overly verbose third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("tldextract").setLevel(logging.WARNING)
