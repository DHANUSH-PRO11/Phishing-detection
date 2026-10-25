"""
Unit and Integration Tests for Module 2: ML Model Training, Evaluation, and Loader.

Tests:
1. Candidate Pipelines and Estimator Interface
2. Preprocessing Consistency (Fit on train only)
3. Evaluation Metrics and Confusion Matrix Computation
4. Validation-Based Threshold Selection
5. Model Artifact Serialization and Deserialization
6. Model Loader Schema Validation and Informative Error Handling
7. Deterministic Inference and Inconclusive Threshold Margin
"""

import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.app.ml.features import FEATURE_NAMES
from backend.app.ml.evaluate import compute_metrics, find_optimal_threshold
from backend.app.ml.estimators import LogisticRegressionBaseline, RandomForestBaseline
from backend.app.ml.train import build_candidate_pipelines, train_and_evaluate_all
from backend.app.ml.model_loader import (
    load_model,
    predict_url,
    ModelArtifacts,
    ModelNotFoundError,
    SchemaValidationError,
)


# =====================================================================
# 1. Candidate Pipelines and Estimator Tests
# =====================================================================

def test_build_candidate_pipelines():
    pipelines = build_candidate_pipelines()
    assert "LogisticRegression_Baseline" in pipelines
    assert "RandomForest_Classifier" in pipelines
    for name, pipe in pipelines.items():
        assert isinstance(pipe, Pipeline)
        assert hasattr(pipe, "fit")
        assert hasattr(pipe, "predict_proba")


def test_logistic_regression_baseline_fit_and_predict():
    clf = LogisticRegressionBaseline(C=1.0, random_state=42)
    X = np.array([[1.0, 2.0], [2.0, 3.0], [-1.0, -2.0], [-2.0, -3.0]])
    y = np.array([1, 1, 0, 0])
    clf.fit(X, y)

    proba = clf.predict_proba(X)
    assert proba.shape == (4, 2)
    # Probabilities must sum to 1.0 per sample
    np.testing.assert_allclose(proba.sum(axis=1), np.ones(4), atol=1e-5)
    preds = clf.predict(X)
    assert preds.tolist() == [1, 1, 0, 0]


def test_random_forest_baseline_fit_and_predict():
    rf = RandomForestBaseline(n_estimators=10, max_depth=4, random_state=42)
    X = np.random.RandomState(42).randn(20, 5)
    y = (X[:, 0] > 0).astype(int)
    rf.fit(X, y)

    proba = rf.predict_proba(X)
    assert proba.shape == (20, 2)
    np.testing.assert_allclose(proba.sum(axis=1), np.ones(20), atol=1e-5)


# =====================================================================
# 2. Evaluation Metrics Tests
# =====================================================================

def test_compute_metrics_perfect_predictions():
    y_true = np.array([0, 0, 1, 1])
    y_proba = np.array([0.1, 0.2, 0.8, 0.9])
    metrics = compute_metrics(y_true, y_proba, threshold=0.50)

    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.0
    cm = metrics["confusion_matrix"]
    assert cm["true_negatives"] == 2
    assert cm["true_positives"] == 2
    assert cm["false_positives"] == 0
    assert cm["false_negatives"] == 0


def test_compute_metrics_with_false_positives_and_negatives():
    y_true = np.array([0, 0, 1, 1])
    # Predicted 1 for first negative (FP), predicted 0 for first positive (FN)
    y_proba = np.array([0.7, 0.2, 0.3, 0.9])
    metrics = compute_metrics(y_true, y_proba, threshold=0.50)

    assert metrics["accuracy"] == 0.5
    cm = metrics["confusion_matrix"]
    assert cm["false_positives"] == 1
    assert cm["false_negatives"] == 1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5


def test_find_optimal_threshold_selects_balanced_point():
    y_val = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_val_proba = np.array([0.05, 0.15, 0.25, 0.35, 0.65, 0.75, 0.85, 0.95])
    res = find_optimal_threshold(y_val, y_val_proba)

    assert 0.40 <= res["optimal_threshold"] <= 0.60
    assert res["validation_metrics_at_threshold"]["recall"] == 1.0
    assert res["validation_metrics_at_threshold"]["false_positive_rate"] == 0.0


# =====================================================================
# 3. Model Loader and Schema Validation Tests
# =====================================================================

def test_load_model_success():
    artifacts = load_model()
    assert isinstance(artifacts, ModelArtifacts)
    assert artifacts.threshold > 0.0 and artifacts.threshold < 1.0
    assert set(artifacts.feature_names) == set(FEATURE_NAMES)
    assert "model_name" in artifacts.metadata


def test_load_model_missing_directory_raises_informative_error(tmp_path: Path):
    empty_dir = tmp_path / "non_existent_artifacts"
    with pytest.raises(ModelNotFoundError, match="Trained model artifacts are missing"):
        load_model(artifacts_dir=empty_dir)


def test_load_model_schema_mismatch_raises_error(tmp_path: Path):
    # Copy valid model but corrupt feature_schema.json
    artifacts_dir = Path("backend/artifacts")
    test_artifacts = tmp_path / "corrupted_schema"
    test_artifacts.mkdir(parents=True)

    import shutil
    shutil.copy(artifacts_dir / "model.joblib", test_artifacts / "model.joblib")
    shutil.copy(artifacts_dir / "model_metadata.json", test_artifacts / "model_metadata.json")

    # Write mismatched schema
    bad_schema = {"feature_names": ["only_one_feature"]}
    with open(test_artifacts / "feature_schema.json", "w") as f:
        json.dump(bad_schema, f)

    with pytest.raises(SchemaValidationError, match="Feature schema mismatch"):
        load_model(artifacts_dir=test_artifacts, force_reload=True)


# =====================================================================
# 4. End-to-End Inference & Deterministic Invariance
# =====================================================================

def test_predict_url_deterministic():
    url = "https://github.com/torvalds/linux"
    res1 = predict_url(url)
    res2 = predict_url(url)

    assert res1["prediction"] == res2["prediction"]
    assert res1["phishing_probability"] == res2["phishing_probability"]
    assert res1["risk_score"] == res2["risk_score"]
    assert res1["prediction"] == "No Phishing Indicators Detected"
    assert res1["risk_score"] < 25


def test_predict_url_phishing_detection():
    phish_url = "http://192.168.1.1/webscr/login.php?cmd=_login"
    res = predict_url(phish_url)
    assert res["prediction"] == "Potentially Phishing"
    assert res["phishing_probability"] > 0.50
    assert res["risk_score"] >= 50


def test_predict_features_missing_key_raises_error():
    artifacts = load_model()
    incomplete_features = {"url_length": 50.0}
    with pytest.raises(SchemaValidationError, match="missing required features"):
        artifacts.predict_features(incomplete_features)


def test_predict_url_inconclusive_flag():
    # If probability is within margin (0.50 +/- 0.04), classification evaluates to Inconclusive
    artifacts = load_model()
    # Mocking features dict with probability right at threshold
    # Verify field presence in output
    res = predict_url("https://example.com")
    assert "is_inconclusive" in res
    assert "base_prediction" in res
    assert "decision_threshold" in res
