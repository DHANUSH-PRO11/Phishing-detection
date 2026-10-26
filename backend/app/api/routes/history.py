"""
Scan History and Details Endpoints.
"""

from __future__ import annotations
import csv
import io
import json
import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.db import crud
from backend.app.schemas.history import (
    PaginatedHistoryResponse,
    ScanSummaryItem,
    ScanDetailItem,
    DeleteResponse,
)

router = APIRouter(tags=["History"])


def sanitize_csv_cell(value: Any) -> str:
    """
    Sanitizes string cells written to CSV to neutralize formula injection (CWE-1236).
    If a cell starts with '=', '+', '-', '@', tab, or carriage return, prepends a single quote.
    """
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str


@router.get(
    "/history",
    response_model=PaginatedHistoryResponse,
    summary="Get Paginated Scan History"
)
def get_scan_history(
    page: int = Query(default=1, ge=1, description="Page number starting from 1."),
    size: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)."),
    search: Optional[str] = Query(default=None, description="Search keyword in URL or domain."),
    status: Optional[str] = Query(default=None, description="Filter by status ('Potentially Phishing', etc.)."),
    risk_category: Optional[str] = Query(default=None, description="Filter by risk category ('Low Risk', etc.)."),
    sort_by: str = Query(
        default="created_at",
        pattern="^(created_at|risk_score|url|domain|status|risk_category|model_probability)$",
        description="Field to sort by ('created_at', 'risk_score', 'url', 'domain', 'status', 'risk_category')."
    ),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$", description="Sort order ('asc' or 'desc')."),
    db: Session = Depends(get_db),
) -> PaginatedHistoryResponse:
    """
    Retrieves filtered, searched, and sorted scan history with pagination metadata.
    """
    skip = (page - 1) * size
    records, total = crud.list_scans(
        db,
        skip=skip,
        limit=size,
        search=search,
        status=status,
        risk_category=risk_category,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    items = [
        ScanSummaryItem(
            scan_id=r.scan_id,
            url=r.url,
            domain=r.domain,
            status=r.status,
            is_phishing=r.is_phishing,
            is_inconclusive=r.is_inconclusive,
            risk_score=r.risk_score,
            risk_category=r.risk_category,
            model_name=r.model_name,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in records
    ]

    total_pages = max(1, math.ceil(total / size)) if total > 0 else 1

    return PaginatedHistoryResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=total_pages,
    )


@router.get(
    "/history/export/csv",
    summary="Export Filtered Scan History as CSV"
)
def export_history_csv(
    search: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    risk_category: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> Response:
    """
    Streams filtered scan history as a downloaded CSV file.
    Sanitizes all cells to prevent formula injection (CWE-1236).
    """
    records, _ = crud.list_scans(
        db,
        skip=0,
        limit=5000,
        search=search,
        status=status,
        risk_category=risk_category,
        sort_by="created_at",
        sort_order="desc",
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Timestamp (UTC)", "URL", "Domain", "Status",
        "Risk Score", "Risk Category", "Model Probability", "Model Name"
    ])

    for r in records:
        writer.writerow([
            sanitize_csv_cell(r.scan_id),
            sanitize_csv_cell(r.created_at.isoformat() if r.created_at else ""),
            sanitize_csv_cell(r.url),
            sanitize_csv_cell(r.domain),
            sanitize_csv_cell(r.status),
            r.risk_score,
            sanitize_csv_cell(r.risk_category),
            round(r.model_probability, 4),
            sanitize_csv_cell(r.model_name),
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishing_scan_history.csv"}
    )


def _validate_scan_id_format(scan_id: str) -> None:
    """Validates that scan_id conforms to UUID format."""
    import uuid
    try:
        uuid.UUID(str(scan_id))
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found."
        )


@router.get(
    "/history/{scan_id}",
    response_model=ScanDetailItem,
    summary="Get Individual Scan Details"
)
def get_scan_details(scan_id: str, db: Session = Depends(get_db)) -> ScanDetailItem:
    """
    Returns full details for a scan record, including deserialized components,
    explanations, and features.
    """
    _validate_scan_id_format(scan_id)
    record = crud.get_scan_by_id(db, scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found."
        )

    try:
        components = json.loads(record.components_json)
        explanations = json.loads(record.explanations_json)
        features = json.loads(record.features_json)
    except Exception:
        components, explanations, features = {}, [], {}

    return ScanDetailItem(
        scan_id=record.scan_id,
        url=record.url,
        domain=record.domain,
        status=record.status,
        is_phishing=record.is_phishing,
        is_inconclusive=record.is_inconclusive,
        risk_score=record.risk_score,
        risk_category=record.risk_category,
        model_name=record.model_name,
        created_at=record.created_at.isoformat() if record.created_at else "",
        model_probability=record.model_probability,
        components=components,
        explanations=explanations,
        features=features,
    )


@router.delete(
    "/history/{scan_id}",
    response_model=DeleteResponse,
    summary="Delete a Scan Record"
)
def delete_scan(scan_id: str, db: Session = Depends(get_db)) -> DeleteResponse:
    """
    Deletes a historical scan record from the database.
    """
    _validate_scan_id_format(scan_id)
    success = crud.delete_scan_by_id(db, scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found."
        )

    return DeleteResponse(
        success=True,
        message="Scan record deleted successfully.",
        scan_id=scan_id
    )
