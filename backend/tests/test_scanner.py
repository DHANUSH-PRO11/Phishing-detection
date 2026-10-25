"""
Unit and Integration Tests for Module 3: URL Scanner and Risk Engine.

Tests:
1. Legitimate URL Scanning & Low Risk Classification
2. Phishing URL Threat Detection & Critical Indicators (IP Host, Punycode, @ symbol, lure keywords)
3. Input Validation: Unsupported schemes (javascript:, data:, file:), empty inputs, malformed URLs
4. Clear Separation of Model Probability (0.0 to 1.0) and Risk Score (0 to 100)
5. Explanations: Plain-English findings, threat context, and severity rankings
6. Mandatory Security Notices: HTTPS limitation analysis and safety disclaimer
7. Edge Cases: Scheme normalization, extreme query parameters, whitespace
8. Missing Model Error Handling: Explicit ModelNotFoundError when artifacts absent
"""

import pytest
from pathlib import Path

from backend.app.services.scanner import ScannerService, scan_url
from backend.app.services.risk_engine import RiskEngine
from backend.app.schemas.scan import ScanResponse, RiskBreakdown
from backend.app.ml.model_loader import ModelNotFoundError


# =====================================================================
# 1. Legitimate URL Scanning Tests
# =====================================================================

def test_scan_legitimate_urls():
    legit_urls = [
        "https://github.com/torvalds/linux",
        "https://en.wikipedia.org/wiki/Computer_security",
        "https://docs.python.org/3/library/urllib.parse.html",
    ]
    for url in legit_urls:
        response = scan_url(url)
        assert isinstance(response, ScanResponse)
        assert response.status == "No Phishing Indicators Detected"
        assert response.is_phishing is False
        assert response.risk.final_risk_score < 30
        assert response.risk.risk_category == "Low Risk"
        assert response.risk.model_probability < 0.20


# =====================================================================
# 2. Phishing Threat Detection Tests
# =====================================================================

def test_scan_phishing_ip_address_host():
    ip_url = "http://192.168.1.105/webscr/login.php?cmd=_login"
    response = scan_url(ip_url)

    assert response.status == "Potentially Phishing"
    assert response.is_phishing is True
    assert response.risk.final_risk_score >= 60
    assert response.risk.model_probability > 0.50

    rules = [exp.rule for exp in response.explanations]
    assert "RAW_IP_HOST" in rules
    assert any("Direct IP Address" in exp.title for exp in response.explanations)


def test_scan_phishing_punycode_homograph():
    puny_url = "http://xn--pypal-4ve.com/signin/verify_account.php"
    response = scan_url(puny_url)

    assert response.status == "Potentially Phishing"
    rules = [exp.rule for exp in response.explanations]
    assert "PUNYCODE_HOMOGRAPH" in rules


def test_scan_phishing_credential_at_symbol():
    at_url = "http://support@paypal.com-update.xyz/auth/login"
    response = scan_url(at_url)

    assert response.status == "Potentially Phishing"
    rules = [exp.rule for exp in response.explanations]
    assert "CREDENTIAL_USERINFO_DELIMITER" in rules


def test_scan_phishing_excessive_subdomains_and_lure_keywords():
    lure_url = "http://secure.account.update.banking.spoofed-portal.xyz/login.html"
    response = scan_url(lure_url)

    assert response.status == "Potentially Phishing"
    rules = [exp.rule for exp in response.explanations]
    assert "EXCESSIVE_SUBDOMAINS" in rules or "MULTIPLE_PHISHING_LURE_TOKENS" in rules


# =====================================================================
# 3. Input Validation & Scheme Rejection Tests
# =====================================================================

def test_reject_unsupported_schemes():
    dangerous_inputs = [
        "javascript:alert('xss')",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
        "about:blank",
        "blob:https://example.com/uuid",
    ]
    for payload in dangerous_inputs:
        with pytest.raises(ValueError, match="Unsupported URI scheme"):
            scan_url(payload)


def test_reject_empty_or_whitespace_urls():
    with pytest.raises(ValueError, match="cannot be empty"):
        scan_url("")
    with pytest.raises(ValueError, match="cannot be empty"):
        scan_url("   \n\t  ")


# =====================================================================
# 4. Risk Score vs Model Probability Separation & Documentation
# =====================================================================

def test_risk_score_and_probability_distinction():
    response = scan_url("http://192.168.1.1/webscr/login.php")

    # Model probability must be float in [0.0, 1.0]
    assert 0.0 <= response.risk.model_probability <= 1.0
    # Final risk score must be integer in [0, 100]
    assert isinstance(response.risk.final_risk_score, int)
    assert 0 <= response.risk.final_risk_score <= 100

    # Formulas and caveats must be documented
    assert "Risk Score R in [0, 100]" in response.risk.formula_documentation
    assert "Methodological Boundaries" in response.risk.limitations_caveat


# =====================================================================
# 5. Mandatory Security Notices (HTTPS & Safety Disclaimers)
# =====================================================================

def test_https_analysis_and_safety_disclaimer():
    response = scan_url("https://www.google.com")

    # Explains that HTTPS alone does not establish safety
    assert "HTTPS" in response.https_analysis
    assert "DOES NOT guarantee" in response.https_analysis or "does not establish" in response.https_analysis.lower()

    # Clear disclaimer that the assessment is probabilistic
    assert "Automated Defensive Assessment Notice" in response.safety_disclaimer
    assert "NEVER a guarantee" in response.safety_disclaimer


# =====================================================================
# 6. Edge Cases & Scheme Normalization
# =====================================================================

def test_normalize_scheme_less_input():
    # URL provided without http:// or https://
    response = scan_url("google.com/search?q=infosec")
    assert response.normalized_url == "http://google.com/search?q=infosec"
    assert response.components.domain == "google.com"


def test_extreme_query_string():
    big_query = "https://example.com/portal?" + "&".join(f"param{i}=val{i}" for i in range(25))
    response = scan_url(big_query)
    assert response.components.query != ""
    assert response.features["param_count"] >= 20


# =====================================================================
# 7. Missing Model Error Handling (Zero Fabrication)
# =====================================================================

def test_missing_model_raises_model_not_found(tmp_path: Path):
    empty_dir = tmp_path / "empty_artifacts"
    empty_dir.mkdir()
    scanner = ScannerService(artifacts_dir=empty_dir)

    with pytest.raises(ModelNotFoundError, match="Please train the model"):
        scanner.scan_url("https://example.com")
