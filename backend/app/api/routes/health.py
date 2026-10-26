"""
Health and Readiness Endpoint.
"""

from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.ml.model_loader import load_model, ModelNotFoundError

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Application and ML Model Health Status")
def check_health(response: Response, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Evaluates backend service health, database responsiveness, and model readiness.
    Sets HTTP 503 if degraded, or HTTP 200 if fully operational.
    """
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    model_ready = False
    model_name = "Unavailable"
    try:
        artifacts = load_model()
        model_ready = True
        model_name = artifacts.metadata.get("model_name", "Trained_Classifier")
    except ModelNotFoundError:
        model_ready = False

    overall_status = "ok" if (db_ok and model_ready) else "degraded"
    if overall_status != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": overall_status,
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database_connected": db_ok,
        "model_ready": model_ready,
        "model_name": model_name,
    }


@router.get("/health/liveness", summary="Container Liveness Probe")
def check_liveness() -> Dict[str, str]:
    """
    Ultra-lightweight liveness probe for Kubernetes and reverse proxies.
    Returns HTTP 200 immediately if the event loop is responsive.
    """
    return {"status": "alive"}


@router.get("/health/readiness", summary="Service Readiness Probe")
def check_readiness(response: Response, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Readiness probe for load balancers (e.g., Nginx, Envoy, K8s).
    Returns HTTP 200 only if DB is responsive and ML model pipeline is loaded.
    Returns HTTP 503 Service Unavailable if unready so traffic is diverted.
    """
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    model_ready = False
    try:
        load_model()
        model_ready = True
    except Exception:
        model_ready = False

    if not (db_ok and model_ready):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unready", "database": db_ok, "model": model_ready}

    return {"status": "ready", "database": db_ok, "model": model_ready}
