"""
Pydantic Schemas for Dashboard Analytics and Aggregates.
"""

from __future__ import annotations
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class TimelineItem(BaseModel):
    scan_id: str
    domain: str
    status: str
    risk_score: int
    timestamp: str | None


class TopDomainItem(BaseModel):
    domain: str
    count: int


class StatsResponse(BaseModel):
    """Real aggregate metrics computed directly from stored records."""
    total_scans: int
    phishing_detected_count: int
    legitimate_count: int
    inconclusive_count: int
    average_risk_score: float
    status_distribution: Dict[str, int]
    risk_category_distribution: Dict[str, int]
    recent_scans_timeline: List[TimelineItem]
    top_flagged_domains: List[TopDomainItem]
