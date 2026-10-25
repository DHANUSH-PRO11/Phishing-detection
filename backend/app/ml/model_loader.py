"""
Model Loader and Schema Validation Service.

Safely loads, verifies, and executes serialized machine learning pipelines.
Provides strict schema validation, deterministic probability inference,
and informative error handling when model artifacts are missing.
"""

from __future__ import annotations
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline

from backend.app.ml.features import FeatureExtractor, FEATURE_NAMES

logger = logging.getLogger(__name__)

DEFAULT_ARTIFACTS_DIR = Path("backend/artifacts")


class ModelNotFoundError(FileNotFoundError):
    """Raised when expected trained model artifacts are missing from disk."""
    pass


class SchemaValidationError(ValueError):
    """Raised when model feature schema or configuration is invalid or corrupted."""
    pass


@dataclass
class ModelArtifacts:
    """Encapsulates a verified, loaded ML pipeline and its metadata."""
    pipeline: Pipeline
    feature_names: List[str]
    threshold: float
    metadata: Dict[str, Any]
    artifacts_dir: Path

    def predict_features(self, features_dict: Dict[str, float]) -> Tuple[float, str]:
        """
        Runs model inference on a dictionary of numeric features.
        Returns:
            probability (float): Model's calibrated phishing probability in [0.0, 1.0]
            prediction (str): 'Potentially Phishing' or 'No Phishing Indicators Detected'
        """
        # Validate that all expected features are present
        missing = [f for f in self.feature_names if f not in features_dict]
        if missing:
            raise SchemaValidationError(f"Inference input is missing required features: {missing}")

        # Assemble DataFrame with strict feature column ordering matching training schema
        df = pd.DataFrame([[features_dict[name] for name in self.feature_names]], columns=self.feature_names)

        # Predict probability for positive class (1 = Phishing)
        proba = float(self.pipeline.predict_proba(df)[0, 1])

        if proba >= self.threshold:
            prediction = "Potentially Phishing"
        else:
            prediction = "No Phishing Indicators Detected"

        return proba, prediction


# Module-level cache for high-throughput API inference
_LOADED_ARTIFACTS: Optional[ModelArtifacts] = None


def load_model(artifacts_dir: str | Path | None = None, force_reload: bool = False) -> ModelArtifacts:
    """
    Safely loads and validates serialized model, feature schema, and metadata.
    Raises ModelNotFoundError with clear guidance if files are absent.
    """
    global _LOADED_ARTIFACTS
    target_dir = Path(artifacts_dir) if artifacts_dir else DEFAULT_ARTIFACTS_DIR

    if _LOADED_ARTIFACTS is not None and not force_reload and _LOADED_ARTIFACTS.artifacts_dir == target_dir:
        return _LOADED_ARTIFACTS

    model_path = target_dir / "model.joblib"
    schema_path = target_dir / "feature_schema.json"
    metadata_path = target_dir / "model_metadata.json"

    # Explicit artifact availability verification
    missing_files = []
    for p in (model_path, schema_path, metadata_path):
        if not p.exists():
            missing_files.append(str(p))

    if missing_files:
        raise ModelNotFoundError(
            f"Trained model artifacts are missing: {missing_files}. "
            "Please run 'python backend/app/ml/train.py' to train, evaluate, and serialize the model."
        )

    # 1. Load Feature Schema and validate against runtime FEATURE_NAMES
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_data = json.load(f)
        feature_names = schema_data.get("feature_names", [])
    except Exception as exc:
        raise SchemaValidationError(f"Failed to parse feature schema at {schema_path}: {exc}") from exc

    if not feature_names or not isinstance(feature_names, list):
        raise SchemaValidationError(f"Invalid feature schema: 'feature_names' must be a non-empty list.")

    if set(feature_names) != set(FEATURE_NAMES):
        diff = set(feature_names).symmetric_difference(set(FEATURE_NAMES))
        raise SchemaValidationError(f"Feature schema mismatch between serialized model and codebase: {diff}")

    # 2. Load Model Metadata
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        threshold = float(metadata.get("optimal_threshold", 0.50))
    except Exception as exc:
        raise SchemaValidationError(f"Failed to parse model metadata at {metadata_path}: {exc}") from exc

    if not (0.0 < threshold < 1.0):
        raise SchemaValidationError(f"Invalid decision threshold {threshold}; must be strictly in (0.0, 1.0).")

    # 3. Load Scikit-Learn Pipeline
    try:
        pipeline = joblib.load(model_path)
    except Exception as exc:
        raise SchemaValidationError(f"Failed to deserialize model pipeline at {model_path}: {exc}") from exc

    if not hasattr(pipeline, "predict_proba"):
        raise SchemaValidationError(f"Loaded pipeline {type(pipeline)} does not implement 'predict_proba'.")

    artifacts = ModelArtifacts(
        pipeline=pipeline,
        feature_names=feature_names,
        threshold=threshold,
        metadata=metadata,
        artifacts_dir=target_dir,
    )

    _LOADED_ARTIFACTS = artifacts
    logger.info("Successfully loaded ML model '%s' with threshold %.2f", metadata.get("model_name"), threshold)
    return artifacts


def predict_url(
    url: str,
    artifacts: Optional[ModelArtifacts] = None,
    extractor: Optional[FeatureExtractor] = None,
) -> Dict[str, Any]:
    """
    End-to-end inference for a URL string:
    - Extracts features offline
    - Computes model probability using serialized champion pipeline
    - Evaluates prediction against validation-tuned decision threshold
    - Identifies inconclusive/borderline cases within margin
    """
    model_obj = artifacts or load_model()
    ext = extractor or FeatureExtractor()

    # Extract all 29 features
    features = ext.extract(url)

    # Predict probability and classification
    proba, prediction = model_obj.predict_features(features)

    # Inconclusive evaluation (within close vicinity of threshold, e.g. +/- 0.04)
    margin = 0.04
    is_inconclusive = abs(proba - model_obj.threshold) <= margin
    final_prediction = "Inconclusive" if is_inconclusive else prediction

    # Calibrated 0-100 risk score
    # Scales probability to an intuitive 0-100 risk integer
    risk_score = round(proba * 100)

    return {
        "url": str(url),
        "prediction": final_prediction,
        "base_prediction": prediction,
        "is_inconclusive": is_inconclusive,
        "phishing_probability": round(proba, 4),
        "risk_score": risk_score,
        "decision_threshold": model_obj.threshold,
        "model_name": model_obj.metadata.get("model_name", "Unknown"),
        "features": features,
    }
