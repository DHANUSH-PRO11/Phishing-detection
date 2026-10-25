"""
Pydantic Schemas for Model Information, Metadata, and Feature Schemas.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ModelInfoResponse(BaseModel):
    """Actual model identity, hyperparameters, threshold, and evaluation metrics."""
    status: str
    model_name: str
    algorithm: str
    optimal_threshold: float
    trained_timestamp: str | None = None
    random_seed: int | None = None
    dataset_sizes: Dict[str, int] = Field(default_factory=dict)
    test_metrics: Dict[str, Any] = Field(default_factory=dict)
    threshold_rationale: str | None = None
    feature_count: int
    feature_names: List[str]
    features_metadata: Dict[str, Any] = Field(default_factory=dict)
    environment: Dict[str, str] = Field(default_factory=dict)
