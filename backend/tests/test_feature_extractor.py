import pytest
from backend.app.ml.feature_extractor import FeatureExtractor, FEATURE_COLUMNS, calculate_entropy, is_ip_address, normalize_url


def test_normalize_url():
    assert normalize_url("google.com") == "http://google.com"
    assert normalize_url("  https://secure.bank.com/login  ") == "https://secure.bank.com/login"
    assert normalize_url("") == ""


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1:8080") is True
    assert is_ip_address("[2001:db8::1]:443") is True
    assert is_ip_address("paypal.com") is False
    assert is_ip_address("192.168.1.1.evil.com") is False


def test_calculate_entropy():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaa") == 0.0
    assert calculate_entropy("abcdefgh") > 2.5


def test_feature_extractor_returns_all_columns():
    extractor = FeatureExtractor()
    features = extractor.extract_features("https://github.com/torvalds/linux")
    assert isinstance(features, dict)
    for col in FEATURE_COLUMNS:
        assert col in features, f"Missing feature column: {col}"
    assert len(features) == len(FEATURE_COLUMNS)


def test_ip_address_feature_detection():
    extractor = FeatureExtractor()
    features = extractor.extract_features("http://192.168.0.100/admin/login.php")
    assert features["has_ip_address"] == 1.0
    assert features["has_https"] == 0.0
    assert features["suspicious_token_count"] >= 2.0


def test_punycode_and_homograph_detection():
    extractor = FeatureExtractor()
    features = extractor.extract_features("http://xn--apple-q2a.com/support")
    assert features["has_punycode"] == 1.0


def test_url_shortener_detection():
    extractor = FeatureExtractor()
    features = extractor.extract_features("https://bit.ly/3x8ZbPq")
    assert features["is_shortened"] == 1.0


def test_suspicious_tld_detection():
    extractor = FeatureExtractor()
    features = extractor.extract_features("http://account-login-verification.xyz/auth")
    assert features["num_sensitive_tlds"] == 1.0


def test_inspect_url_structure_and_flags():
    extractor = FeatureExtractor()
    inspection = extractor.inspect_url("http://192.168.1.1/webscr/login.php?cmd=_login-run")
    assert "components" in inspection
    assert "features" in inspection
    assert "flags" in inspection
    flag_types = [f["type"] for f in inspection["flags"]]
    assert "IP_HOSTNAME" in flag_types
    assert "PHISHING_KEYWORDS" in flag_types or "PHISHING_KEYWORD" in flag_types
