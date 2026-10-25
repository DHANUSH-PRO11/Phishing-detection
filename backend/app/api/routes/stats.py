"""
Dashboard Aggregate Statistics Endpoint.
"""

from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.db import crud
from backend.app.schemas.stats import StatsResponse

router = APIRouter(tags=["Statistics"])


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Get Real Aggregate Scan Statistics"
)
def get_dashboard_stats(db: Session = Depends(get_db)) -> StatsResponse:
    """
    Computes real aggregate scan statistics from stored database records:
    - Total scans
    - Phishing vs legitimate breakdown
    - Average risk score
    - Status & risk category distributions
    - Recent scans timeline
    - Top flagged phishing domains
    """
    stats_data = crud.get_aggregate_statistics(db)
    return StatsResponse(**stats_data)
