"""
Custom Scikit-Learn-Compatible Estimators for Phishing URL Detection.

Provides pure-Python/NumPy/SciPy implementations of:
- LogisticRegressionBaseline (L2 regularized with L-BFGS-B optimization)
- RandomForestBaseline (Breiman's Random Forest with bootstrapping and random subspace)

These ensure guaranteed cross-platform reproducibility and resilience against
operating system Application Control / WDAC DLL block policies.
"""

from __future__ import annotations
from typing import Any, Dict, List, Tuple
import numpy as np
import scipy.optimize
from sklearn.base import BaseEstimator, ClassifierMixin

RANDOM_SEED = 42


class LogisticRegressionBaseline(BaseEstimator, ClassifierMixin):
    """
    Scikit-Learn-compatible L2-regularized Logistic Regression baseline.
    Uses exact negative log-likelihood minimization via SciPy's L-BFGS-B.
    """
    def __init__(self, C: float = 1.0, max_iter: int = 1000, random_state: int = RANDOM_SEED) -> None:
        self.C = C
        self.max_iter = max_iter
        self.random_state = random_state
        self.classes_ = np.array([0, 1])

    def fit(self, X: Any, y: Any) -> "LogisticRegressionBaseline":
        X_mat = np.asarray(X, dtype=float)
        y_vec = np.asarray(y, dtype=float)
        n_samples, n_features = X_mat.shape
        l2_reg = 1.0 / max(self.C, 1e-5)

        def loss_and_grad(w: np.ndarray) -> Tuple[float, np.ndarray]:
            bias = w[0]
            weights = w[1:]
            z = np.clip(X_mat @ weights + bias, -35.0, 35.0)
            p = 1.0 / (1.0 + np.exp(-z))
            p = np.clip(p, 1e-15, 1.0 - 1e-15)
            # Binary cross entropy + L2 penalty
            loss = -np.mean(y_vec * np.log(p) + (1.0 - y_vec) * np.log(1.0 - p)) + 0.5 * l2_reg * np.sum(weights ** 2) / n_samples
            error = (p - y_vec) / n_samples
            grad_b = float(np.sum(error))
            grad_w = (X_mat.T @ error) + (l2_reg * weights / n_samples)
            return loss, np.concatenate(([grad_b], grad_w))

        rng = np.random.RandomState(self.random_state)
        w0 = rng.normal(0, 0.01, size=n_features + 1)
        res = scipy.optimize.minimize(loss_and_grad, w0, jac=True, method="L-BFGS-B", options={"maxiter": self.max_iter})
        self.intercept_ = float(res.x[0])
        self.coef_ = res.x[1:].reshape(1, -1)
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        X_mat = np.asarray(X, dtype=float)
        z = np.clip(X_mat @ self.coef_[0] + self.intercept_, -35.0, 35.0)
        p1 = 1.0 / (1.0 + np.exp(-z))
        p0 = 1.0 - p1
        return np.column_stack([p0, p1])

    def predict(self, X: Any) -> np.ndarray:
        proba = self.predict_proba(X)
        return (proba[:, 1] >= 0.5).astype(int)


class _SimpleDecisionTree:
    """Lightweight single decision tree node for random forest ensemble."""
    def __init__(self, max_depth: int = 6, min_samples_split: int = 2, max_features: int | None = None, rng: Any = None) -> None:
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.rng = rng or np.random.RandomState()

    def fit(self, X: np.ndarray, y: np.ndarray, depth: int = 0) -> Dict[str, Any]:
        n_samples, n_features = X.shape
        p1 = float(np.mean(y)) if n_samples > 0 else 0.5
        if depth >= self.max_depth or n_samples < self.min_samples_split or len(np.unique(y)) <= 1:
            return {"leaf": True, "prob": p1}

        feat_indices = np.arange(n_features)
        if self.max_features and self.max_features < n_features:
            feat_indices = self.rng.choice(feat_indices, size=self.max_features, replace=False)

        best_gini = 1.0
        best_split = None

        for feat in feat_indices:
            vals = np.unique(X[:, feat])
            if len(vals) <= 1:
                continue
            thresholds = (vals[:-1] + vals[1:]) / 2.0
            if len(thresholds) > 10:
                thresholds = self.rng.choice(thresholds, size=10, replace=False)

            for thresh in thresholds:
                left_mask = X[:, feat] <= thresh
                right_mask = ~left_mask
                if left_mask.sum() == 0 or right_mask.sum() == 0:
                    continue

                p_l = np.mean(y[left_mask])
                p_r = np.mean(y[right_mask])
                gini_l = 1.0 - (p_l ** 2 + (1.0 - p_l) ** 2)
                gini_r = 1.0 - (p_r ** 2 + (1.0 - p_r) ** 2)
                weighted_gini = (left_mask.sum() * gini_l + right_mask.sum() * gini_r) / n_samples

                if weighted_gini < best_gini:
                    best_gini = weighted_gini
                    best_split = (feat, thresh, left_mask, right_mask)

        if best_split is None:
            return {"leaf": True, "prob": p1}

        feat, thresh, left_mask, right_mask = best_split
        left_sub = self.fit(X[left_mask], y[left_mask], depth + 1)
        right_sub = self.fit(X[right_mask], y[right_mask], depth + 1)
        return {"leaf": False, "feat": feat, "thresh": thresh, "left": left_sub, "right": right_sub, "prob": p1}

    def predict_one(self, node: Dict[str, Any], x: np.ndarray) -> float:
        if node["leaf"]:
            return float(node["prob"])
        if x[node["feat"]] <= node["thresh"]:
            return self.predict_one(node["left"], x)
        return self.predict_one(node["right"], x)


class RandomForestBaseline(BaseEstimator, ClassifierMixin):
    """
    Scikit-Learn-compatible Random Forest classifier with bootstrapping
    and random subspace feature selection (Breiman's Random Forest).
    """
    def __init__(self, n_estimators: int = 50, max_depth: int = 6, min_samples_split: int = 2, random_state: int = RANDOM_SEED) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.random_state = random_state
        self.classes_ = np.array([0, 1])
        self.trees: List[Tuple[_SimpleDecisionTree, Dict[str, Any]]] = []

    def fit(self, X: Any, y: Any) -> "RandomForestBaseline":
        X_mat = np.asarray(X, dtype=float)
        y_vec = np.asarray(y, dtype=float)
        n_samples, n_features = X_mat.shape
        max_features = max(1, int(np.sqrt(n_features)))
        rng = np.random.RandomState(self.random_state)
        self.trees = []

        for _ in range(self.n_estimators):
            boot_idx = rng.choice(n_samples, size=n_samples, replace=True)
            tree_rng = np.random.RandomState(rng.randint(0, 1000000))
            dt = _SimpleDecisionTree(self.max_depth, self.min_samples_split, max_features, tree_rng)
            node = dt.fit(X_mat[boot_idx], y_vec[boot_idx])
            self.trees.append((dt, node))
        return self

    def predict_proba(self, X: Any) -> np.ndarray:
        X_mat = np.asarray(X, dtype=float)
        all_probs: List[List[float]] = []
        for dt, node in self.trees:
            probs = [dt.predict_one(node, row) for row in X_mat]
            all_probs.append(probs)
        p1 = np.mean(all_probs, axis=0)
        p0 = 1.0 - p1
        return np.column_stack([p0, p1])

    def predict(self, X: Any) -> np.ndarray:
        proba = self.predict_proba(X)
        return (proba[:, 1] >= 0.5).astype(int)
