"""
Health and Readiness Endpoint.
"""

from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.ml.model_loader import load_model, ModelNotFoundError

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Application and ML Model Health Status")
def check_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Evaluates backend service health, database responsiveness, and model readiness.
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

    return {
        "status": overall_status,
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database_connected": db_ok,
        "model_ready": model_ready,
        "model_name": model_name,
    }
