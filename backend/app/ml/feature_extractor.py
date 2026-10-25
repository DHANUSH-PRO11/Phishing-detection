"""
URL Feature Extraction Engine.

Extracts lexical, structural, statistical, and domain features locally
without performing outbound DNS queries, HTTP requests, or remote executions.
Defensive cybersecurity tool for offline, secure URL classification.
"""

from __future__ import annotations
import math
import re
from typing import Any, Dict, List, Tuple
import urllib.parse
import ipaddress
import tldextract

# List of known URL shortening domains
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "shorte.st",
    "v.gd", "tr.im", "prettylinkpro.com", "clickmeter.com", "adf.ly"
}

# TLDs historically associated with high abuse rates and free/disposable domain registration
HIGH_ABUSE_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "buzz", "top", "xyz", "work", "fit",
    "club", "rest", "surf", "tokyo", "download", "racing", "kim", "country"
}

# Suspicious keywords commonly found in phishing lures
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "update", "banking", "secure", "security",
    "account", "signin", "sign-in", "confirm", "confirmation", "password", "wallet",
    "billing", "support", "token", "service", "ebayisapi", "webscr", "admin",
    "authenticate", "authorization", "re-activate", "credential", "session", "appleid",
    "paypal", "chase", "wellsfargo", "bankofamerica", "netflix", "microsoft", "outlook"
]

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equal_signs",
    "num_at_symbols",
    "num_ampersands",
    "num_percent_signs",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_ip_address",
    "has_https",
    "is_shortened",
    "entropy",
    "suspicious_token_count",
    "num_sensitive_tlds",
    "has_double_slash_in_path",
    "has_punycode",
    "num_parameters",
    "num_fragments",
    "ratio_vowels_to_consonants",
    "longest_token_length",
]


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon character entropy of a given string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address (excluding port)."""
    if not host:
        return False
    if host.startswith("["):
        host_clean = host.split("]")[0].lstrip("[")
    elif ":" in host and host.count(":") == 1:
        host_clean = host.split(":")[0]
    else:
        host_clean = host.strip("[]")
    try:
        ipaddress.ip_address(host_clean)
        return True
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    """
    Normalizes a URL string for consistent parsing and inspection.
    Strips leading/trailing whitespace and prepends 'http://' if scheme is missing.
    """
    clean_url = url.strip()
    if not clean_url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "http://" + clean_url
    return clean_url


class FeatureExtractor:
    """
    Robust, offline URL feature extractor returning numeric feature arrays
    and detailed diagnostic metadata.
    """

    def __init__(self) -> None:
        # Cache tldextract extractor offline mode (no network updates during inference)
        self.extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

    def extract_features(self, raw_url: str) -> Dict[str, float]:
        """
        Extract numeric feature dictionary for machine learning models.
        """
        clean_url = normalize_url(raw_url)
        parsed = urllib.parse.urlparse(clean_url)
        extracted = self.extractor(clean_url)

        host = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        url_len = len(clean_url)
        reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        domain = reg_domain or host
        subdomain = extracted.subdomain or ""
        suffix = extracted.suffix.lower() if extracted.suffix else ""

        # Digit statistics
        num_digits = sum(c.isdigit() for c in clean_url)
        digit_ratio = (num_digits / url_len) if url_len > 0 else 0.0

        # Subdomain count
        subdomain_parts = [p for p in subdomain.split(".") if p]
        num_subdomains = len(subdomain_parts)

        # Host checks
        has_ip = 1.0 if is_ip_address(host) else 0.0
        has_https = 1.0 if parsed.scheme.lower() == "https" else 0.0
        is_shortened = 1.0 if (domain.lower() in KNOWN_SHORTENERS or host.lower() in KNOWN_SHORTENERS) else 0.0
        has_punycode = 1.0 if ("xn--" in host.lower() or "xn--" in clean_url.lower()) else 0.0

        # Suspicious keyword counting across path and query
        searchable_content = f"{path.lower()} {query.lower()} {subdomain.lower()}"
        suspicious_token_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in searchable_content)

        # TLD check
        num_sensitive_tlds = 1.0 if (suffix in HIGH_ABUSE_TLDS) else 0.0

        # Structural anomalies
        has_double_slash_path = 1.0 if ("//" in path) else 0.0

        # Query parameter count
        num_params = len(urllib.parse.parse_qs(query)) if query else 0

        # Vowel to consonant ratio in domain
        domain_letters = [c.lower() for c in domain if c.isalpha()]
        vowels = sum(1 for c in domain_letters if c in "aeiou")
        consonants = len(domain_letters) - vowels
        vowel_ratio = (vowels / max(consonants, 1)) if domain_letters else 0.0

        # Longest token in URL
        tokens = re.split(r"[/._?=&%#\-~]", clean_url)
        longest_token = max((len(t) for t in tokens if t), default=0)

        return {
            "url_length": float(url_len),
            "domain_length": float(len(host)),
            "path_length": float(len(path)),
            "query_length": float(len(query)),
            "num_dots": float(clean_url.count(".")),
            "num_hyphens": float(clean_url.count("-")),
            "num_underscores": float(clean_url.count("_")),
            "num_slashes": float(clean_url.count("/")),
            "num_question_marks": float(clean_url.count("?")),
            "num_equal_signs": float(clean_url.count("=")),
            "num_at_symbols": float(clean_url.count("@")),
            "num_ampersands": float(clean_url.count("&")),
            "num_percent_signs": float(clean_url.count("%")),
            "num_digits": float(num_digits),
            "digit_ratio": round(digit_ratio, 4),
            "num_subdomains": float(num_subdomains),
            "has_ip_address": has_ip,
            "has_https": has_https,
            "is_shortened": is_shortened,
            "entropy": calculate_entropy(clean_url),
            "suspicious_token_count": float(suspicious_token_count),
            "num_sensitive_tlds": num_sensitive_tlds,
            "has_double_slash_in_path": has_double_slash_path,
            "has_punycode": has_punycode,
            "num_parameters": float(num_params),
            "num_fragments": float(len(fragment)),
            "ratio_vowels_to_consonants": round(vowel_ratio, 4),
            "longest_token_length": float(longest_token),
        }

    def inspect_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Extract detailed structural decomposition, numeric features,
        and flagged indicators for explainability.
        """
        clean_url = normalize_url(raw_url)
        parsed = urllib.parse.urlparse(clean_url)
        extracted = self.extractor(clean_url)
        numeric_features = self.extract_features(raw_url)

        host = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # Identify explicit structural warning flags
        flags: List[Dict[str, str]] = []
        if numeric_features["has_ip_address"] == 1.0:
            flags.append({
                "type": "IP_HOSTNAME",
                "severity": "HIGH",
                "message": f"URL hostname '{host}' is a raw IP address instead of a registered domain name."
            })
        if numeric_features["num_at_symbols"] > 0:
            flags.append({
                "type": "CREDENTIAL_AT_SYMBOL",
                "severity": "HIGH",
                "message": "URL contains '@' symbol, which browsers interpret as userinfo, obscuring the actual destination."
            })
        if numeric_features["is_shortened"] == 1.0:
            flags.append({
                "type": "URL_SHORTENER",
                "severity": "MEDIUM",
                "message": f"URL uses a known link shortener ({host}) which hides the real target destination."
            })
        if numeric_features["num_sensitive_tlds"] == 1.0:
            flags.append({
                "type": "SUSPICIOUS_TLD",
                "severity": "MEDIUM",
                "message": f"URL uses high-abuse top-level domain '.{extracted.suffix}'."
            })
        if numeric_features["num_subdomains"] >= 3:
            flags.append({
                "type": "EXCESSIVE_SUBDOMAINS",
                "severity": "MEDIUM",
                "message": f"Host contains {int(numeric_features['num_subdomains'])} subdomains, often used to spoof legitimate brand names."
            })
        if numeric_features["has_punycode"] == 1.0:
            flags.append({
                "type": "PUNYCODE_HOMOGRAPH",
                "severity": "HIGH",
                "message": "URL contains Punycode ('xn--'), frequently used in internationalized domain homograph attacks."
            })
        if numeric_features["has_double_slash_in_path"] == 1.0:
            flags.append({
                "type": "DOUBLE_SLASH_REDIRECT",
                "severity": "MEDIUM",
                "message": "URL contains '//' in the path, which can trigger client-side open redirects."
            })
        if numeric_features["suspicious_token_count"] >= 2:
            flags.append({
                "type": "PHISHING_KEYWORDS",
                "severity": "HIGH",
                "message": f"Detected {int(numeric_features['suspicious_token_count'])} sensitive keywords commonly used in credential harvesting lures."
            })
        elif numeric_features["suspicious_token_count"] == 1:
            flags.append({
                "type": "PHISHING_KEYWORD",
                "severity": "LOW",
                "message": "Detected sensitive credential keyword in URL path or query."
            })
        if numeric_features["entropy"] > 4.5:
            flags.append({
                "type": "HIGH_ENTROPY",
                "severity": "MEDIUM",
                "message": f"URL character entropy ({numeric_features['entropy']:.2f}) is high, indicating possible algorithmic randomness or obfuscation."
            })

        return {
            "normalized_url": clean_url,
            "components": {
                "scheme": parsed.scheme,
                "netloc": host,
                "domain": f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain,
                "subdomain": extracted.subdomain,
                "tld": extracted.suffix,
                "path": path,
                "query": query,
                "fragment": parsed.fragment,
            },
            "features": numeric_features,
            "flags": flags,
        }
