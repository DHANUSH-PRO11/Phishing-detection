"""
URL Scanning API Endpoint.
"""

from __future__ import annotations
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.db import crud
from backend.app.schemas.scan import ScanRequest, ScanResponse
from backend.app.services.scanner import scan_url
from backend.app.ml.model_loader import ModelNotFoundError

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Scanner"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan and Analyze a URL"
)
def scan_url_endpoint(payload: ScanRequest, db: Session = Depends(get_db)) -> ScanResponse:
    """
    Analyzes a URL string offline:
    - Extracts 29 lexical and structural features
    - Runs ML probability inference
    - Synthesizes a calibrated 0-100 Risk Score
    - Generates plain-English findings
    - Persists the completed assessment to the database
    """
    try:
        scan_result = scan_url(payload.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc)
        ) from exc
    except ModelNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trained machine learning model is currently unavailable. Please run model training before scanning."
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected error during URL scanning")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while evaluating the URL. Please verify formatting and try again."
        ) from exc

    # Persist scan result to database
    try:
        record = crud.create_scan_record(db, scan_result)
        scan_result.scan_id = record.scan_id
    except Exception as exc:
        logger.warning("Failed to persist scan record to database: %s", exc)

    return scan_result
