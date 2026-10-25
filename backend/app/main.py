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

    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Defensive cybersecurity REST API for offline lexical and structural "
            "URL feature extraction, machine learning classification, and calibrated "
            "0-100 risk scoring with plain-English explainability."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS configuration with explicitly approved origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
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
