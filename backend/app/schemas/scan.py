"""
Pydantic Schemas for URL Scanning and Risk Assessment.

Defines strict request validation and rich structured response models
providing explainable cybersecurity assessments.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanRequest(BaseModel):
    """URL scan submission payload."""
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="Raw URL string to scan and evaluate offline."
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty or whitespace.")
        # Reject dangerous schemes that cannot be scanned as standard web resources
        lower = clean.lower()
        unsupported = ("javascript:", "data:", "file:", "vbscript:", "about:", "blob:")
        if lower.startswith(unsupported):
            raise ValueError(f"Unsupported URI scheme. Only HTTP and HTTPS web URLs are permitted.")
        return clean


class URLComponents(BaseModel):
    """Decomposed structural components of the URL."""
    scheme: str = Field(..., description="Protocol scheme (http, https).")
    netloc: str = Field(..., description="Hostname and optional port.")
    domain: str = Field(..., description="Registered domain name under public suffix.")
    subdomain: str = Field(..., description="Subdomain labels.")
    suffix: str = Field(..., description="Public suffix / Top Level Domain (TLD).")
    path: str = Field(..., description="Path segment.")
    query: str = Field(..., description="Query string parameters.")
    fragment: str = Field(..., description="URL fragment / anchor.")


class FeatureItem(BaseModel):
    """Detailed metadata and diagnostic evaluation for an individual feature."""
    name: str
    value: float
    description: str
    threat_rationale: str
    is_flagged: bool = False
    flag_reason: Optional[str] = None


class ExplanationItem(BaseModel):
    """Human-readable explainability indicator detailing an observed threat or security characteristic."""
    rule: str = Field(..., description="Machine-readable rule identifier.")
    title: str = Field(..., description="Human-friendly finding headline.")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL.")
    message: str = Field(..., description="Clear explanation of the observed characteristic.")
    threat_context: str = Field(..., description="Cybersecurity rationale explaining how attackers exploit this.")


class RiskBreakdown(BaseModel):
    """
    Transparent breakdown of the 0-100 risk score calculation,
    distinguishing model probability from composite application risk.
    """
    model_probability: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Raw probability output from the trained ML pipeline (0.0 to 1.0)."
    )
    decision_threshold: float = Field(
        ...,
        description="Operating threshold selected on validation data (default: 0.50)."
    )
    heuristic_penalty: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Additive risk penalty from verified structural red flags (IP hosts, punycode, etc.)."
    )
    final_risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calibrated composite cybersecurity risk index from 0 to 100."
    )
    risk_category: str = Field(
        ...,
        description="Qualitative risk classification: 'Low Risk', 'Medium Risk', 'High Risk', or 'Critical Risk'."
    )
    formula_documentation: str = Field(
        ...,
        description="Exact mathematical formula used to synthesize model probability and heuristic penalties."
    )
    limitations_caveat: str = Field(
        ...,
        description="Documentation of methodological limitations and threat model boundaries."
    )


class ScanResponse(BaseModel):
    """Complete scan assessment response model."""
    scan_id: Optional[str] = Field(default=None, description="Unique UUID assigned to this persisted scan.")
    url: str
    normalized_url: str
    status: str = Field(
        ...,
        description="Primary prediction status: 'Potentially Phishing', 'No Phishing Indicators Detected', or 'Inconclusive'."
    )
    is_phishing: bool
    is_inconclusive: bool
    risk: RiskBreakdown
    https_analysis: str = Field(
        ...,
        description="Specific explanation regarding TLS/HTTPS status (e.g. why HTTPS alone does not establish safety)."
    )
    safety_disclaimer: str = Field(
        ...,
        description="Affirmation that this assessment is an automated ML evaluation, not a guarantee of safety."
    )
    components: URLComponents
    explanations: List[ExplanationItem]
    features: Dict[str, float]
    feature_details: List[FeatureItem]
    model_name: str
    scan_timestamp_utc: str
