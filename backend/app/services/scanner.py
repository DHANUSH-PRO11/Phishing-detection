"""
URL Scanning and Analysis Service.

Orchestrates offline feature extraction, model inference, risk engine evaluation,
and human-readable cybersecurity explanations.
Strictly adheres to defensive security principles:
- Analyzes URLs offline as static strings
- Never sends HTTP/DNS queries to the target domain
- Validates input schemas and sanitizes outputs
- Refuses to fabricate predictions if the trained model is unavailable
"""

from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import urllib.parse
import tldextract

from backend.app.schemas.scan import (
    ScanResponse,
    URLComponents,
)
from backend.app.ml.features import (
    FeatureExtractor,
    normalize_url_string,
    is_ip_host,
    extract_pure_hostname,
    redact_url_credentials,
)
from backend.app.ml.model_loader import (
    load_model,
    ModelArtifacts,
    ModelNotFoundError,
    SchemaValidationError,
)
from backend.app.services.risk_engine import RiskEngine
from backend.app.services.explanations import (
    ExplanationEngine,
    HTTPS_ANALYSIS_TEXT,
    SAFETY_DISCLAIMER_TEXT,
)

logger = logging.getLogger(__name__)


class ScannerService:
    """
    Main cybersecurity scanner service coordinating feature extraction,
    risk evaluation, and explainability.
    """

    def __init__(self, artifacts_dir: Optional[Path] = None) -> None:
        self.artifacts_dir = artifacts_dir
        self.feature_extractor = FeatureExtractor()
        # Offline TLD extractor
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

    def scan_url(self, raw_url: str) -> ScanResponse:
        """
        Scans a single URL string and returns a comprehensive, explainable ScanResponse.
        Never establishes an outbound network connection.
        """
        # 1. Clean, validate, and normalize input string
        clean_url = raw_url.strip() if raw_url else ""
        if not clean_url:
            raise ValueError("URL string cannot be empty.")

        import re
        clean_url = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", clean_url)
        if not clean_url:
            raise ValueError("URL contains only unprintable control characters.")

        # Reject unsupported schemes: only standard HTTP/HTTPS web URLs can be analyzed
        lower_url = clean_url.lower()
        if ":" in lower_url:
            scheme_candidate = lower_url.split(":", 1)[0].strip()
            if "/" not in scheme_candidate and scheme_candidate not in ("http", "https"):
                raise ValueError(
                    f"Unsupported URI scheme '{scheme_candidate}'. Only standard HTTP/HTTPS web URLs can be analyzed."
                )

        normalized_url = normalize_url_string(clean_url)
        if not normalized_url:
            raise ValueError("Provided URL is malformed or unparseable.")

        # 2. Decompose URL components
        try:
            parsed = urllib.parse.urlparse(normalized_url)
        except Exception:
            parsed = urllib.parse.urlsplit(normalized_url)

        # Enforce valid scheme
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(
                f"Unsupported URI scheme '{parsed.scheme}'. Only standard HTTP/HTTPS web URLs can be analyzed."
            )

        # Enforce non-empty hostname/netloc
        pure_host = extract_pure_hostname(parsed.netloc or "")
        if not pure_host:
            raise ValueError("Provided URL is missing a valid destination hostname or authority.")

        extracted = self.tld_extractor(normalized_url)
        raw_netloc = parsed.netloc or ""
        reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        # Sanitize credentials from persisted netloc and components
        sanitized_netloc = redact_url_credentials(raw_netloc)
        sanitized_raw_url = redact_url_credentials(raw_url)
        sanitized_normalized_url = redact_url_credentials(normalized_url)

        components = URLComponents(
            scheme=parsed.scheme,
            netloc=sanitized_netloc,
            domain=reg_domain or pure_host,
            subdomain=extracted.subdomain,
            suffix=extracted.suffix,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
        )

        # 3. Extract exact numeric feature schema reusing pre-computed TLD extraction
        features = self.feature_extractor.extract(normalized_url, tld_result=extracted)

        # 4. Perform ML model inference using serialized champion model
        # Explicit error reporting if model has not been trained
        try:
            model_artifacts = load_model(artifacts_dir=self.artifacts_dir)
            proba, _ = model_artifacts.predict_features(features)
            threshold = model_artifacts.threshold
            model_name = model_artifacts.metadata.get("model_name", "Trained_Classifier")
        except ModelNotFoundError as exc:
            logger.error("Model artifacts unavailable: %s", exc)
            raise ModelNotFoundError(
                f"Model artifacts not found. Please train the model using 'python backend/app/ml/train.py' before scanning."
            ) from exc

        # 5. Evaluate Composite Risk Breakdown (0-100)
        risk = RiskEngine.evaluate_risk(
            model_probability=proba,
            decision_threshold=threshold,
            features=features
        )

        # 6. Determine Primary Status
        status, is_phish, is_inconc = RiskEngine.determine_status(risk)

        # 7. Generate Explanations and Enriched Feature Details
        explanations = ExplanationEngine.generate_explanations(
            features=features,
            components=components.model_dump(),
        )
        feature_details = ExplanationEngine.compile_feature_details(features)

        # 8. Assemble Complete Structured Response (with credentials redacted)
        response = ScanResponse(
            url=sanitized_raw_url,
            normalized_url=sanitized_normalized_url,
            status=status,
            is_phishing=is_phish,
            is_inconclusive=is_inconc,
            risk=risk,
            https_analysis=HTTPS_ANALYSIS_TEXT,
            safety_disclaimer=SAFETY_DISCLAIMER_TEXT,
            components=components,
            explanations=explanations,
            features=features,
            feature_details=feature_details,
            model_name=model_name,
            scan_timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )

        return response


# Module-level singleton
_DEFAULT_SCANNER = ScannerService()


def scan_url(url: str) -> ScanResponse:
    """Convenience top-level function for scanning a URL."""
    return _DEFAULT_SCANNER.scan_url(url)
