"""
Model Evaluation and Threshold Optimization Suite.

Computes comprehensive cybersecurity classification metrics:
- Precision, Phishing Recall, F1-Score
- False Positive Rate (FPR), False Negative Rate (FNR)
- Precision-Recall AUC (PR-AUC) and ROC-AUC
- Confusion Matrix (TN, FP, FN, TP)
- Class-wise metrics
- Validation-based threshold search prioritizing Phishing Recall with constrained FPR.
"""

from __future__ import annotations
from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
)


def compute_metrics(
    y_true: np.ndarray | List[int],
    y_proba: np.ndarray | List[float],
    threshold: float = 0.50,
) -> Dict[str, Any]:
    """
    Computes full set of binary classification metrics at a given decision threshold.
    Zero fabricated numbers; uses scikit-learn standard evaluators.
    """
    y_true = np.asarray(y_true).astype(int)
    y_proba = np.asarray(y_proba).astype(float)
    y_pred = (y_proba >= threshold).astype(int)

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    total_negatives = tn + fp
    total_positives = tp + fn

    fpr = (fp / total_negatives) if total_negatives > 0 else 0.0
    fnr = (fn / total_positives) if total_positives > 0 else 0.0

    # Probability-based area metrics (independent of single threshold)
    try:
        roc_auc = float(roc_auc_score(y_true, y_proba))
    except ValueError:
        roc_auc = 0.0

    try:
        pr_auc = float(average_precision_score(y_true, y_proba))
    except ValueError:
        pr_auc = 0.0

    # Class-wise report
    report_dict = classification_report(
        y_true, y_pred, labels=[0, 1], target_names=["Legitimate (0)", "Phishing (1)"], output_dict=True, zero_division=0
    )

    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "class_metrics": {
            "legitimate_0": {
                "precision": round(float(report_dict["Legitimate (0)"]["precision"]), 4),
                "recall": round(float(report_dict["Legitimate (0)"]["recall"]), 4),
                "f1_score": round(float(report_dict["Legitimate (0)"]["f1-score"]), 4),
                "support": int(report_dict["Legitimate (0)"]["support"]),
            },
            "phishing_1": {
                "precision": round(float(report_dict["Phishing (1)"]["precision"]), 4),
                "recall": round(float(report_dict["Phishing (1)"]["recall"]), 4),
                "f1_score": round(float(report_dict["Phishing (1)"]["f1-score"]), 4),
                "support": int(report_dict["Phishing (1)"]["support"]),
            },
        },
    }


def find_optimal_threshold(
    y_val: np.ndarray | List[int],
    y_val_proba: np.ndarray | List[float],
    min_recall: float = 0.85,
    max_fpr: float = 0.15,
) -> Dict[str, Any]:
    """
    Sweeps decision thresholds on validation data to select an operating point
    that prioritizes phishing recall while keeping false positive rate within bounds.

    Never fitted on test data.
    """
    y_val = np.asarray(y_val).astype(int)
    y_val_proba = np.asarray(y_val_proba).astype(float)

    threshold_candidates = np.linspace(0.10, 0.90, 81)
    best_threshold = 0.50
    best_score = -1.0
    best_metrics: Dict[str, Any] = {}
    tradeoff_history: List[Dict[str, float]] = []

    for thresh in threshold_candidates:
        metrics = compute_metrics(y_val, y_val_proba, threshold=thresh)
        rec = metrics["recall"]
        prec = metrics["precision"]
        f1 = metrics["f1_score"]
        fpr = metrics["false_positive_rate"]

        tradeoff_history.append({
            "threshold": round(float(thresh), 2),
            "recall": rec,
            "precision": prec,
            "f1": f1,
            "fpr": fpr,
        })

        # Selection objective:
        # Prioritize F1 while heavily penalizing if recall drops below min_recall or fpr exceeds max_fpr.
        # Break ties by penalizing extreme distance from central 0.50 threshold to avoid brittle boundary thresholds.
        score = f1
        if rec < min_recall:
            score -= (min_recall - rec) * 2.0
        if fpr > max_fpr:
            score -= (fpr - max_fpr) * 2.0

        # Small tie-breaker preferring stable operating points near 0.50
        tie_breaker = -0.01 * abs(float(thresh) - 0.50)
        composite_score = score + tie_breaker

        if composite_score > best_score:
            best_score = composite_score
            best_threshold = thresh
            best_metrics = metrics

    # Fallback to 0.50 if candidate search didn't find positive score
    if not best_metrics:
        best_threshold = 0.50
        best_metrics = compute_metrics(y_val, y_val_proba, threshold=0.50)

    return {
        "optimal_threshold": round(float(best_threshold), 4),
        "validation_metrics_at_threshold": best_metrics,
        "selection_rationale": (
            f"Selected threshold {best_threshold:.2f} on validation set: "
            f"achieves Phishing Recall={best_metrics['recall']:.2%}, "
            f"Precision={best_metrics['precision']:.2%}, "
            f"F1={best_metrics['f1_score']:.2%}, "
            f"and False Positive Rate={best_metrics['false_positive_rate']:.2%}."
        ),
        "threshold_sweep_sample": tradeoff_history[::10],  # Sample points for documentation
    }
