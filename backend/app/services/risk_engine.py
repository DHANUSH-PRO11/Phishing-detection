"""
Cybersecurity Risk Engine.

Synthesizes machine learning probability estimates with deterministic
structural red flags into a calibrated 0-100 Risk Score.
Transparently documents calculation formulas and methodology boundaries.
"""

from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.app.schemas.scan import RiskBreakdown


FORMULA_DOCUMENTATION = (
    "Risk Score R in [0, 100] is calculated as: "
    "R = min(100, round(0.70 * (P_model * 100) + H_penalties)), where P_model is the "
    "calibrated statistical probability from the trained classifier, and H_penalties "
    "represents additive severity weights for verified structural anomalies (e.g. raw IP host: +30, "
    "punycode homograph: +25, credential '@': +25, shortener: +15, high-abuse TLD: +15, "
    "double slash redirect: +15, multiple credential keywords: +15)."
)

LIMITATIONS_CAVEAT = (
    "Methodological Boundaries: This analysis is performed strictly on lexical and structural "
    "properties of the submitted URL string without establishing an outbound connection to the "
    "target host. Consequently, this engine cannot detect malicious payloads embedded inside "
    "downloadable files, compromised legitimate websites, or dynamic client-side JavaScript cloaking."
)


class RiskEngine:
    """Calculates calibrated composite risk scores and qualitative severity categories."""

    HEURISTIC_WEIGHTS = {
        "has_ip_host": 30.0,
        "has_at_symbol": 25.0,
        "has_punycode": 25.0,
        "has_double_slash_path": 15.0,
        "is_shortened": 15.0,
        "has_abused_tld": 15.0,
    }

    @classmethod
    def calculate_heuristic_penalty(cls, features: Dict[str, float]) -> Tuple[float, List[Dict[str, Any]]]:
        """Calculates additive heuristic penalties from structural threat indicators."""
        total_penalty = 0.0
        applied_penalties: List[Dict[str, Any]] = []

        for feature_key, weight in cls.HEURISTIC_WEIGHTS.items():
            if features.get(feature_key, 0.0) == 1.0:
                total_penalty += weight
                applied_penalties.append({
                    "indicator": feature_key,
                    "penalty": weight,
                })

        # Excessive subdomains (>= 3)
        subdomains = features.get("subdomain_count", 0.0)
        if subdomains >= 3:
            penalty = 10.0
            total_penalty += penalty
            applied_penalties.append({
                "indicator": "excessive_subdomains",
                "penalty": penalty,
            })

        # Suspicious credential keywords (>= 2)
        kw_count = features.get("suspicious_keyword_count", 0.0)
        if kw_count >= 2:
            penalty = 15.0
            total_penalty += penalty
            applied_penalties.append({
                "indicator": "multiple_suspicious_keywords",
                "penalty": penalty,
            })
        elif kw_count == 1:
            penalty = 5.0
            total_penalty += penalty
            applied_penalties.append({
                "indicator": "single_suspicious_keyword",
                "penalty": penalty,
            })

        # High character entropy (> 4.6)
        entropy = features.get("char_entropy", 0.0)
        if entropy > 4.6:
            penalty = 10.0
            total_penalty += penalty
            applied_penalties.append({
                "indicator": "high_entropy",
                "penalty": penalty,
            })

        return min(total_penalty, 60.0), applied_penalties

    @classmethod
    def evaluate_risk(
        cls,
        model_probability: float,
        decision_threshold: float,
        features: Dict[str, float]
    ) -> RiskBreakdown:
        """
        Synthesizes model probability and structural indicators into a comprehensive RiskBreakdown.
        """
        clamped_prob = max(0.0, min(1.0, float(model_probability)))
        heuristic_penalty, _ = cls.calculate_heuristic_penalty(features)

        # Baseline risk component from statistical ML model (scaled 0-100)
        # We blend 70% model probability with additive structural penalties
        raw_score = (0.70 * (clamped_prob * 100.0)) + heuristic_penalty
        final_risk = int(round(max(0.0, min(100.0, raw_score))))

        # Determine qualitative category
        if final_risk >= 85:
            category = "Critical Risk"
        elif final_risk >= 60:
            category = "High Risk"
        elif final_risk >= 30:
            category = "Medium Risk"
        else:
            category = "Low Risk"

        return RiskBreakdown(
            model_probability=round(clamped_prob, 4),
            decision_threshold=round(float(decision_threshold), 4),
            heuristic_penalty=round(heuristic_penalty, 2),
            final_risk_score=final_risk,
            risk_category=category,
            formula_documentation=FORMULA_DOCUMENTATION,
            limitations_caveat=LIMITATIONS_CAVEAT,
        )

    @classmethod
    def determine_status(
        cls,
        risk: RiskBreakdown,
        margin: float = 0.04
    ) -> Tuple[str, bool, bool]:
        """
        Determines the official prediction status:
        - 'Potentially Phishing'
        - 'No Phishing Indicators Detected'
        - 'Inconclusive'

        Returns:
            (status_string, is_phishing_bool, is_inconclusive_bool)
        """
        prob = risk.model_probability
        thresh = risk.decision_threshold
        final_score = risk.final_risk_score

        # If high risk or probability exceeds threshold, classify as Potentially Phishing
        if final_score >= 60 or prob >= thresh:
            return "Potentially Phishing", True, False

        # Inconclusive check: Probability is close to decision threshold (+/- margin)
        # AND no major structural red flags exist to disambiguate
        if abs(prob - thresh) <= margin and final_score < 50:
            return "Inconclusive", False, True

        return "No Phishing Indicators Detected", False, False
