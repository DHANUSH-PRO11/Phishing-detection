"""
FastAPI Application Entrypoint.

Configures middleware, CORS security, lifecycle event handlers,
global sanitized exception handling, and API routing.
"""

from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.core.config import settings
from backend.app.core.logging import setup_logging
from backend.app.db.database import init_db
from backend.app.ml.model_loader import load_model, ModelNotFoundError
from backend.app.api.routes import (
    health,
    scan,
    history,
    stats,
    model_info,
)

logger = logging.getLogger("phishing_detection_app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    # 1. Initialize logging
    setup_logging()
    logger.info("Initializing %s in [%s] environment...", settings.APP_NAME, settings.APP_ENV)

    # 2. Initialize database schema
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc)

    # 3. Pre-load ML model into memory
    try:
        load_model()
        logger.info("ML model pipeline pre-loaded and validated.")
    except ModelNotFoundError as exc:
        logger.warning("ML model not pre-loaded: %s", exc)
    except Exception as exc:
        logger.error("Failed to load ML model during startup: %s", exc)

    yield

    logger.info("Application shutdown completed.")


def create_application() -> FastAPI:
    """Factory function for FastAPI application instance."""
    # Ensure database schema is created
    init_db()

    # Disable interactive documentation in production to prevent endpoint reconnaissance
    is_production = settings.APP_ENV.lower() == "production" and not settings.DEBUG
    docs_url = None if is_production else "/docs"
    redoc_url = None if is_production else "/redoc"
    openapi_url = None if is_production else "/openapi.json"

    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Defensive cybersecurity REST API for offline lexical and structural "
            "URL feature extraction, machine learning classification, and calibrated "
            "0-100 risk scoring with plain-English explainability."
        ),
        version="1.0.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    from starlette.middleware.base import BaseHTTPMiddleware
    from backend.app.core.rate_limiter import RateLimitMiddleware

    # Request body size limiting middleware (defense against DoS / resource exhaustion)
    class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
        def __init__(self, app_inst, max_bytes: int = 1_048_576):
            super().__init__(app_inst)
            self.max_bytes = max_bytes

        async def dispatch(self, request: Request, call_next):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.max_bytes:
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content={
                                "error": "Payload Too Large",
                                "detail": f"Request body exceeds the maximum permitted size of {self.max_bytes // 1024} KB.",
                            },
                        )
                except ValueError:
                    pass
            return await call_next(request)

    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=1_048_576)

    # CORS configuration with explicitly approved origins
    cors_origins = [o for o in settings.ALLOWED_ORIGINS if o != "*"] if "*" in settings.ALLOWED_ORIGINS else settings.ALLOWED_ORIGINS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["http://localhost:5173", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )

    # In-memory sliding window rate limiter and security headers
    app.add_middleware(
        RateLimitMiddleware,
        max_requests=settings.RATE_LIMIT_PER_MINUTE,
        window_seconds=60,
    )

    # Global Sanitized Exception Handlers (Preventing stack trace and path leaks)
    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Validation Error", "detail": str(exc)},
        )

    @app.exception_handler(ModelNotFoundError)
    async def model_not_found_handler(request: Request, exc: ModelNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": "Service Unavailable", "detail": str(exc)},
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled server exception at %s %s", request.method, request.url.path)
        # Never leak internal traces or file paths to client
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred while processing the request. Our security team has logged the event."
            },
        )

    # Register API routers under /api
    prefix = settings.API_PREFIX
    app.include_router(health.router, prefix=prefix)
    app.include_router(scan.router, prefix=prefix)
    app.include_router(history.router, prefix=prefix)
    app.include_router(stats.router, prefix=prefix)
    app.include_router(model_info.router, prefix=prefix)

    @app.get("/", summary="Root Metadata Endpoint")
    def root() -> dict:
        return {
            "app_name": settings.APP_NAME,
            "version": "1.0.0",
            "status": "active",
            "documentation": "/docs",
            "health_endpoint": f"{prefix}/health",
            "scan_endpoint": f"{prefix}/scan",
        }

    return app


app = create_application()
