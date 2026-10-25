"""
Pydantic Schemas for Scan History and Details.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScanSummaryItem(BaseModel):
    """Compact summary of a scan for tabular history views."""
    scan_id: str
    url: str
    domain: str
    status: str
    is_phishing: bool
    is_inconclusive: bool
    risk_score: int
    risk_category: str
    model_name: str
    created_at: str


class ScanDetailItem(ScanSummaryItem):
    """Detailed scan view with deserialized features, components, and explanations."""
    model_probability: float
    components: Dict[str, Any]
    explanations: List[Dict[str, Any]]
    features: Dict[str, float]


class PaginatedHistoryResponse(BaseModel):
    """Paginated list of historical scans with metadata."""
    items: List[ScanSummaryItem]
    total: int
    page: int
    size: int
    pages: int


class DeleteResponse(BaseModel):
    """Response confirming scan record deletion."""
    success: bool
    message: str
    scan_id: str
