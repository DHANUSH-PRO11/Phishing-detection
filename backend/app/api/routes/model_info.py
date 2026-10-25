"""
Model Information and Evaluation Metadata Endpoint.
"""

from __future__ import annotations
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException, status

from backend.app.core.config import settings
from backend.app.schemas.model_info import ModelInfoResponse
from backend.app.ml.features import FEATURE_NAMES, FEATURE_METADATA

router = APIRouter(tags=["Model Info"])


@router.get(
    "/model-info",
    response_model=ModelInfoResponse,
    summary="Get Active Model Information and Metrics"
)
@router.get(
    "/model/info",
    response_model=ModelInfoResponse,
    include_in_schema=False
)
def get_model_information() -> ModelInfoResponse:
    """
    Exposes authentic model provenance, training metadata, selected threshold,
    unbiased test evaluation metrics, and feature schemas.
    """
    artifacts_dir = Path(settings.MODEL_DIR)
    metadata_path = artifacts_dir / "model_metadata.json"
    schema_path = artifacts_dir / "feature_schema.json"

    if not (metadata_path.exists() and schema_path.exists()):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model metadata is unavailable. Please run 'python backend/app/ml/train.py'."
        )

    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read model metadata: {exc}"
        ) from exc

    return ModelInfoResponse(
        status="active",
        model_name=meta.get("model_name", "Trained_Classifier"),
        algorithm=meta.get("algorithm", "LogisticRegression"),
        optimal_threshold=float(meta.get("optimal_threshold", 0.50)),
        trained_timestamp=meta.get("trained_timestamp"),
        random_seed=meta.get("random_seed"),
        dataset_sizes=meta.get("dataset_sizes", {}),
        test_metrics=meta.get("test_metrics", {}),
        threshold_rationale=meta.get("threshold_rationale"),
        feature_count=len(FEATURE_NAMES),
        feature_names=FEATURE_NAMES,
        features_metadata=FEATURE_METADATA,
        environment=meta.get("environment", {}),
    )
