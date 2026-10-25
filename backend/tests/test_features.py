"""
Unit and Integration Tests for Module 1: URL Feature Extraction & Data Pipeline.

Tests:
1. URL Normalization and Sanitization
2. Safe Handling of Malformed and Extreme Inputs
3. Feature Types, Bounds, and Schema Completeness
4. Lexical and Structural Threat Indicator Detection
5. Dataset Pipeline Label Validation, Deduplication, and Auditing
6. Deterministic Stratified Splitting and Zero Sample Leakage
"""

import math
import pytest
import pandas as pd
from pathlib import Path

from backend.app.ml.features import (
    FeatureExtractor,
    FEATURE_NAMES,
    FEATURE_METADATA,
    calculate_entropy,
    is_ip_host,
    normalize_url_string,
    extract_url_features,
    inspect_url,
)
from backend.app.ml.dataset import DatasetPipeline


# =====================================================================
# 1. URL Normalization and Sanitization Tests
# =====================================================================

def test_normalize_url_standard():
    assert normalize_url_string("https://google.com") == "https://google.com"
    assert normalize_url_string("http://example.com/login") == "http://example.com/login"


def test_normalize_url_missing_scheme():
    assert normalize_url_string("github.com/torvalds") == "http://github.com/torvalds"
    assert normalize_url_string("192.168.1.1/admin") == "http://192.168.1.1/admin"


def test_normalize_url_whitespace_and_control_chars():
    dirty = "   \n\r\t http://test.com/path\x00\x1f  "
    clean = normalize_url_string(dirty)
    assert clean == "http://test.com/path"


def test_normalize_url_empty_and_none():
    assert normalize_url_string("") == ""
    assert normalize_url_string("    ") == ""
    assert normalize_url_string(None) == ""


def test_normalize_url_non_string():
    assert normalize_url_string(12345) == "http://12345"


# =====================================================================
# 2. Malformed and Extreme Inputs Tests
# =====================================================================

def test_extract_features_none_and_empty():
    extractor = FeatureExtractor()
    feat_empty = extractor.extract("")
    assert isinstance(feat_empty, dict)
    assert len(feat_empty) == len(FEATURE_NAMES)
    assert all(val == 0.0 for val in feat_empty.values())

    feat_none = extractor.extract(None)
    assert len(feat_none) == len(FEATURE_NAMES)


def test_extract_features_severely_malformed_url():
    extractor = FeatureExtractor()
    malformed_urls = [
        ":///invalid-path?query=yes",
        "http://",
        "http:///path-only",
        "http://???&&&###",
        "ftp://user:pass@/broken",
        "http://[::ffff:invalid:ip]/test",
    ]
    for url in malformed_urls:
        features = extractor.extract(url)
        assert isinstance(features, dict)
        assert len(features) == len(FEATURE_NAMES)
        for key, val in features.items():
            assert isinstance(val, (int, float))
            assert not math.isnan(val)


def test_extract_features_extreme_length():
    extractor = FeatureExtractor()
    huge_url = "http://example.com/" + ("a" * 10000) + "?token=" + ("b" * 5000)
    features = extractor.extract(huge_url)
    assert features["url_length"] > 15000
    assert features["path_length"] >= 10000
    assert features["query_length"] >= 5000


# =====================================================================
# 3. Feature Types, Bounds, and Schema Completeness
# =====================================================================

def test_feature_names_match_metadata():
    assert set(FEATURE_NAMES) == set(FEATURE_METADATA.keys())
    assert len(FEATURE_NAMES) == 29


def test_feature_types_and_bounds():
    extractor = FeatureExtractor()
    sample_urls = [
        "https://www.google.com/search?q=cybersecurity&hl=en#top",
        "http://192.168.1.10:8080/login.php?user=admin&token=4892#section",
        "http://paypal-verification.xyz/auth/verify?id=992",
    ]
    for url in sample_urls:
        features = extractor.extract(url)
        assert len(features) == len(FEATURE_NAMES)
        for name in FEATURE_NAMES:
            val = features[name]
            assert isinstance(val, float), f"{name} is not a float"
            assert not math.isnan(val), f"{name} is NaN"

        # Check bounds
        assert 0.0 <= features["digit_ratio"] <= 1.0
        assert features["char_entropy"] >= 0.0
        assert features["has_ip_host"] in (0.0, 1.0)
        assert features["has_https"] in (0.0, 1.0)
        assert features["has_at_symbol"] in (0.0, 1.0)
        assert features["is_shortened"] in (0.0, 1.0)
        assert features["has_abused_tld"] in (0.0, 1.0)
        assert features["has_punycode"] in (0.0, 1.0)


# =====================================================================
# 4. Lexical and Structural Threat Indicators
# =====================================================================

def test_ip_host_detection():
    assert is_ip_host("192.168.1.1") is True
    assert is_ip_host("10.0.0.1:8080") is True
    assert is_ip_host("[2001:db8::1]:443") is True
    assert is_ip_host("google.com") is False
    assert is_ip_host("192.168.1.1.attacker.com") is False

    extractor = FeatureExtractor()
    features = extractor.extract("http://192.168.1.1/webscr/login.php")
    assert features["has_ip_host"] == 1.0


def test_punycode_homograph_detection():
    extractor = FeatureExtractor()
    features = extractor.extract("http://xn--pypal-4ve.com/signin")
    assert features["has_punycode"] == 1.0


def test_credential_at_symbol_detection():
    extractor = FeatureExtractor()
    features = extractor.extract("http://admin@chase.com-support.com/auth")
    assert features["has_at_symbol"] == 1.0
    assert features["at_count"] == 1.0


def test_url_shortener_detection():
    extractor = FeatureExtractor()
    features = extractor.extract("https://bit.ly/3x8ZbPq")
    assert features["is_shortened"] == 1.0


def test_suspicious_tld_detection():
    extractor = FeatureExtractor()
    features = extractor.extract("http://paypal-verification.xyz/login.html")
    assert features["has_abused_tld"] == 1.0


def test_suspicious_keyword_counting():
    extractor = FeatureExtractor()
    features = extractor.extract("http://example.com/account/login/verify/update")
    assert features["suspicious_keyword_count"] >= 3.0


def test_double_slash_path_detection():
    extractor = FeatureExtractor()
    features = extractor.extract("http://example.com//redirect?target=phish")
    assert features["has_double_slash_path"] == 1.0


def test_char_entropy_calculation():
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaa") == 0.0
    # Random alphanumeric string should have higher entropy than repetitive string
    low_ent = calculate_entropy("http://example.com/aaaaaaaaaa")
    high_ent = calculate_entropy("http://example.com/8f9a2b7c4d1e9f0a2b4c")
    assert high_ent > low_ent


def test_inspect_url_produces_flags():
    inspection = inspect_url("http://192.168.1.1/login/verify.php?cmd=_login")
    assert "components" in inspection
    assert "features" in inspection
    assert "flags" in inspection
    assert len(inspection["flags"]) >= 1
    rules = [f["rule"] for f in inspection["flags"]]
    assert "IP_HOST_DETECTED" in rules


# =====================================================================
# 5. Dataset Pipeline, Deduplication, and Label Validation
# =====================================================================

def test_pipeline_seed_creation(tmp_path: Path):
    raw_path = tmp_path / "raw_urls.csv"
    pipeline = DatasetPipeline(raw_data_path=raw_path)
    seed_file = pipeline.create_initial_seed_dataset()
    assert seed_file.exists()

    df = pd.read_csv(seed_file)
    assert "url" in df.columns
    assert "label" in df.columns
    assert len(df) >= 50
    assert set(df["label"].unique()) == {0, 1}


def test_pipeline_label_validation(tmp_path: Path):
    bad_csv = tmp_path / "bad.csv"
    df = pd.DataFrame([
        {"url": "https://legit.com", "label": 0},
        {"url": "http://phish.com", "label": 3},  # Invalid label
    ])
    df.to_csv(bad_csv, index=False)

    pipeline = DatasetPipeline(raw_data_path=bad_csv)
    with pytest.raises(ValueError, match="invalid labels"):
        pipeline.load_and_validate()


def test_pipeline_deduplication(tmp_path: Path):
    dup_csv = tmp_path / "duplicates.csv"
    df = pd.DataFrame([
        {"url": "https://example.com/page", "label": 0},
        {"url": "https://example.com/page", "label": 0},  # Duplicate
        {"url": "http://phish-site.com/login", "label": 1},
    ])
    df.to_csv(dup_csv, index=False)

    pipeline = DatasetPipeline(raw_data_path=dup_csv)
    clean_df, audit = pipeline.load_and_validate()
    assert len(clean_df) == 2
    assert audit["duplicate_urls_removed"] == 1


def test_pipeline_conflicted_labels_dropped(tmp_path: Path):
    conflict_csv = tmp_path / "conflict.csv"
    df = pd.DataFrame([
        {"url": "https://ambiguous.com", "label": 0},
        {"url": "https://ambiguous.com", "label": 1},  # Conflicting label
        {"url": "https://clear.com", "label": 0},
    ])
    df.to_csv(conflict_csv, index=False)

    pipeline = DatasetPipeline(raw_data_path=conflict_csv)
    clean_df, audit = pipeline.load_and_validate()
    assert len(clean_df) == 1
    assert clean_df.iloc[0]["url"] == "https://clear.com"
    assert audit["conflicted_labels_dropped"] == 1


# =====================================================================
# 6. Stratified Partitioning and Zero-Leakage Guarantee
# =====================================================================

def test_pipeline_split_and_zero_leakage():
    pipeline = DatasetPipeline()
    clean_df, _ = pipeline.load_and_validate()
    featured_df = pipeline.extract_features_df(clean_df)

    train_df, val_df, test_df = pipeline.split_data(
        featured_df, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, random_seed=42
    )

    # 1. Row count completeness
    assert len(train_df) + len(val_df) + len(test_df) == len(featured_df)

    # 2. Cryptographic zero URL overlap verification
    train_urls = set(train_df["normalized_url"])
    val_urls = set(val_df["normalized_url"])
    test_urls = set(test_df["normalized_url"])

    assert len(train_urls.intersection(val_urls)) == 0, "Train and Val share URLs!"
    assert len(train_urls.intersection(test_urls)) == 0, "Train and Test share URLs!"
    assert len(val_urls.intersection(test_urls)) == 0, "Val and Test share URLs!"

    # 3. Class stratification in all splits
    assert set(train_df["label"].unique()) == {0, 1}
    assert set(val_df["label"].unique()) == {0, 1}
    assert set(test_df["label"].unique()) == {0, 1}


def test_pipeline_deterministic_reproducibility():
    pipeline = DatasetPipeline()
    clean_df, _ = pipeline.load_and_validate()
    featured_df = pipeline.extract_features_df(clean_df)

    train_a, val_a, test_a = pipeline.split_data(featured_df, random_seed=123)
    train_b, val_b, test_b = pipeline.split_data(featured_df, random_seed=123)

    assert train_a["normalized_url"].tolist() == train_b["normalized_url"].tolist()
    assert val_a["normalized_url"].tolist() == val_b["normalized_url"].tolist()
    assert test_a["normalized_url"].tolist() == test_b["normalized_url"].tolist()
