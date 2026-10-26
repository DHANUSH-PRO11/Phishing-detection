"""
URL Feature Extraction Engine.

Defensive lexical and structural feature extraction for phishing URL detection.
Extracts features locally using urllib.parse and tldextract without executing
outbound DNS queries, HTTP connections, or downloading remote assets.
"""

from __future__ import annotations
import math
import re
import ipaddress
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import tldextract

# Well-known URL shorteners frequently abused to obscure target URLs
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "shorte.st",
    "v.gd", "tr.im", "prettylinkpro.com", "clickmeter.com", "adf.ly"
})

# High-abuse TLDs often correlated with free registration and disposable phishing campaigns
HIGH_ABUSE_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "buzz", "top", "xyz", "work", "fit",
    "club", "rest", "surf", "tokyo", "download", "racing", "kim", "country"
})

# Suspicious keywords commonly observed in credential phishing lures
SUSPICIOUS_KEYWORDS = (
    "login", "verify", "verification", "update", "banking", "secure", "security",
    "account", "signin", "sign-in", "confirm", "confirmation", "password", "wallet",
    "billing", "support", "token", "service", "ebayisapi", "webscr", "admin",
    "authenticate", "authorization", "re-activate", "credential", "session",
    "appleid", "paypal", "chase", "wellsfargo", "bankofamerica", "netflix",
    "microsoft", "outlook", "office365", "recover", "passcode"
)

# Detailed documentation and rationale for every extracted feature
FEATURE_METADATA: Dict[str, Dict[str, Any]] = {
    "url_length": {
        "type": "float",
        "description": "Total character length of the normalized URL.",
        "rationale": "Phishing URLs frequently use unusually long paths and query strings to camouflage lures or embed redirect links.",
        "range": "[0, 2048]"
    },
    "hostname_length": {
        "type": "float",
        "description": "Character length of the hostname/netloc.",
        "rationale": "Long hostnames often conceal spoofed brand names within deep subdomains.",
        "range": "[0, 255]"
    },
    "path_length": {
        "type": "float",
        "description": "Character length of the URL path component.",
        "rationale": "Deep directory paths or embedded filenames often simulate authentic corporate portals.",
        "range": "[0, 2048]"
    },
    "query_length": {
        "type": "float",
        "description": "Character length of the URL query string.",
        "rationale": "Complex query strings may carry base64-encoded parameters or victim identifiers.",
        "range": "[0, 2048]"
    },
    "dot_count": {
        "type": "float",
        "description": "Total number of dot (.) characters in the URL.",
        "rationale": "Excessive dots typically indicate multiple subdomain layers or deceptive domain names.",
        "range": "[0, 50]"
    },
    "hyphen_count": {
        "type": "float",
        "description": "Total number of hyphen (-) characters in the URL.",
        "rationale": "Hyphens are widely used in spoofed domain names (e.g., 'paypal-security-update').",
        "range": "[0, 50]"
    },
    "underscore_count": {
        "type": "float",
        "description": "Total number of underscore (_) characters in the URL.",
        "rationale": "Underscores are uncommon in legitimate domains but appear in script parameters and phishing paths.",
        "range": "[0, 50]"
    },
    "slash_count": {
        "type": "float",
        "description": "Total number of forward slash (/) characters in the URL.",
        "rationale": "High slash counts indicate nested paths or path-traversal redirect constructs.",
        "range": "[0, 50]"
    },
    "question_mark_count": {
        "type": "float",
        "description": "Number of question marks (?) in the URL.",
        "rationale": "Legitimate URLs contain at most one delimiter for query parameters; multiple question marks indicate anomalies.",
        "range": "[0, 10]"
    },
    "equal_count": {
        "type": "float",
        "description": "Number of equal sign (=) characters in the URL.",
        "rationale": "Multiple key-value parameters are common in session tracking and tracking redirects.",
        "range": "[0, 50]"
    },
    "at_count": {
        "type": "float",
        "description": "Number of @ characters in the URL.",
        "rationale": "The @ symbol treats preceding characters as user authentication credentials, masking the true host.",
        "range": "[0, 10]"
    },
    "ampersand_count": {
        "type": "float",
        "description": "Number of ampersand (&) characters in the URL.",
        "rationale": "Represents the density of parameters passed in the query string.",
        "range": "[0, 50]"
    },
    "percent_count": {
        "type": "float",
        "description": "Number of percent (%) characters in the URL.",
        "rationale": "Percent encoding is used to obfuscate characters and bypass naive pattern matchers.",
        "range": "[0, 100]"
    },
    "digit_count": {
        "type": "float",
        "description": "Total number of numeric digits in the URL.",
        "rationale": "Phishing URLs often incorporate generated numeric IDs, IP addresses, or hash digests.",
        "range": "[0, 2048]"
    },
    "digit_ratio": {
        "type": "float",
        "description": "Proportion of numeric digits relative to total URL length.",
        "rationale": "Elevated digit proportions suggest automated domain generation or algorithmic parameters.",
        "range": "[0.0, 1.0]"
    },
    "special_char_count": {
        "type": "float",
        "description": "Count of non-alphanumeric characters excluding standard URL delimiters.",
        "rationale": "Unusual punctuation marks, symbols, and operators correlate with malicious payload strings.",
        "range": "[0, 2048]"
    },
    "has_ip_host": {
        "type": "float",
        "description": "Binary flag indicating whether the host is an IPv4 or IPv6 address.",
        "rationale": "Direct IP hosting is a strong red flag; legitimate services rarely ask users to browse directly to raw IPs.",
        "range": "[0.0, 1.0]"
    },
    "has_https": {
        "type": "float",
        "description": "Binary flag indicating whether the URL protocol is HTTPS.",
        "rationale": "Lack of HTTPS indicates unencrypted transport, though modern phishing also adopts free TLS certificates.",
        "range": "[0.0, 1.0]"
    },
    "has_at_symbol": {
        "type": "float",
        "description": "Binary indicator for the presence of the '@' userinfo separator.",
        "rationale": "Direct indicator of browser userinfo spoofing attempts.",
        "range": "[0.0, 1.0]"
    },
    "subdomain_count": {
        "type": "float",
        "description": "Number of subdomain labels separated by dots.",
        "rationale": "Deep subdomain chains allow attackers to create spoof domains like 'paypal.com.attacker.com'.",
        "range": "[0, 20]"
    },
    "is_shortened": {
        "type": "float",
        "description": "Binary flag indicating whether the domain belongs to a known URL shortener.",
        "rationale": "Shorteners mask destination domains and circumvent reputation filters.",
        "range": "[0.0, 1.0]"
    },
    "char_entropy": {
        "type": "float",
        "description": "Shannon character entropy of the URL string.",
        "rationale": "High entropy signifies randomness, DGA (Domain Generation Algorithms), or encoded payloads.",
        "range": "[0.0, 8.0]"
    },
    "suspicious_keyword_count": {
        "type": "float",
        "description": "Count of keywords associated with credential harvesting and banking lures.",
        "rationale": "Attackers frequently rely on urgency words ('login', 'verify', 'account', 'update') in paths.",
        "range": "[0, 50]"
    },
    "has_abused_tld": {
        "type": "float",
        "description": "Binary flag indicating whether the TLD is on the high-abuse registration list.",
        "rationale": "Free and low-cost TLDs (e.g., .tk, .xyz, .buzz) have high historical abuse concentrations.",
        "range": "[0.0, 1.0]"
    },
    "has_double_slash_path": {
        "type": "float",
        "description": "Binary flag indicating '//' in the URL path component.",
        "rationale": "Double slashes in paths can induce client-side redirection vulnerabilities.",
        "range": "[0.0, 1.0]"
    },
    "has_punycode": {
        "type": "float",
        "description": "Binary flag indicating punycode ('xn--') in hostname.",
        "rationale": "Punycode enables internationalized domain name (IDN) homograph attacks spoofing similar characters.",
        "range": "[0.0, 1.0]"
    },
    "param_count": {
        "type": "float",
        "description": "Count of discrete query parameters.",
        "rationale": "High parameter counts are typical in tracking, redirection, and token-passing scripts.",
        "range": "[0, 50]"
    },
    "fragment_length": {
        "type": "float",
        "description": "Character length of the URL fragment (#).",
        "rationale": "Client-side fragments are rarely sent to servers but can execute client script payloads.",
        "range": "[0, 255]"
    },
    "longest_token_length": {
        "type": "float",
        "description": "Length of the longest contiguous alphanumeric segment in the URL.",
        "rationale": "Excessively long alphanumeric tokens reflect hashes, session IDs, or encoded payloads.",
        "range": "[0, 500]"
    }
}

FEATURE_NAMES = list(FEATURE_METADATA.keys())


def calculate_entropy(text: str) -> float:
    """Calculate Shannon character entropy of a given text string."""
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


def extract_pure_hostname(authority_or_url: str) -> str:
    """
    Safely extracts the pure hostname without userinfo credentials, port, or IPv6 brackets.
    Handles user:pass@host:port, [::1]:port, and standard hostnames cleanly without network calls.
    """
    if not authority_or_url:
        return ""
    clean = authority_or_url.strip()
    # Strip URL scheme if whole URL was provided
    if "://" in clean:
        clean = clean.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    elif "/" in clean:
        clean = clean.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    # Strip user credentials preceding '@'
    if "@" in clean:
        clean = clean.split("@")[-1]

    # Handle bracketed IPv6 address e.g. [::1]:8080 or [::1]
    if clean.startswith("["):
        bracket_end = clean.find("]")
        if bracket_end != -1:
            return clean[1:bracket_end]
        return clean.lstrip("[").split(":")[0]

    # Strip port if present
    if ":" in clean:
        # If multiple colons without brackets, it could be a raw IPv6 address (e.g. ::1)
        if clean.count(":") > 1:
            return clean
        return clean.split(":")[0]

    return clean


def get_ip_address_obj(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Safely parses an IP address object from a host string, returning None if not an IP."""
    pure = extract_pure_hostname(host)
    if not pure:
        return None
    try:
        return ipaddress.ip_address(pure)
    except ValueError:
        return None


def is_ip_host(host: str) -> bool:
    """
    Check if a given host string represents an IPv4 or IPv6 address.
    Robustly handles user credentials (user:pass@host), ports, and bracket wrappers.
    """
    return get_ip_address_obj(host) is not None


def is_private_or_loopback_ip(host: str) -> bool:
    """
    Check if a host represents a loopback, private, link-local, or cloud metadata address.
    Defends against SSRF, intranet probes, and cloud metadata exploitation (169.254.169.254).
    """
    ip_obj = get_ip_address_obj(host)
    if ip_obj is not None:
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_unspecified
        )
    pure = extract_pure_hostname(host).lower()
    return pure in ("localhost", "0.0.0.0", "127.0.0.1", "::1")


def check_punycode_or_idn(host: str, clean_url: str) -> bool:
    """
    Detects Punycode or Internationalized Domain Name (IDN) homograph attacks.
    Checks for explicit 'xn--' prefix as well as raw Unicode homoglyphs in hostname.
    """
    if "xn--" in clean_url.lower():
        return True
    pure = extract_pure_hostname(host)
    if "xn--" in pure.lower():
        return True
    # Test if hostname contains non-ASCII characters or encodes to IDNA 'xn--'
    if any(ord(c) > 127 for c in pure):
        return True
    try:
        idna_encoded = pure.encode("idna").decode("ascii")
        if "xn--" in idna_encoded.lower():
            return True
    except Exception:
        if any(ord(c) > 127 for c in pure):
            return True
    return False


def redact_url_credentials(url_or_netloc: str) -> str:
    """
    Redacts sensitive user credentials (passwords) from URL authority components
    to prevent logging, storage, or reflection of plaintext secrets.
    """
    if not url_or_netloc:
        return ""
    # Pattern to match scheme://user:pass@host or user:pass@host
    def _sub(match):
        prefix = match.group(1) or ""
        user = match.group(2) or ""
        password = match.group(3)
        host_part = match.group(4) or ""
        if password is not None:
            return f"{prefix}{user}:[REDACTED]@{host_part}"
        elif user:
            return f"{prefix}[REDACTED]@{host_part}"
        return match.group(0)

    pattern = r"^([a-zA-Z][a-zA-Z0-9+.-]*://)?([^/:@]+)(?::([^@]+))?@(.+)$"
    return re.sub(pattern, _sub, url_or_netloc)



def normalize_url_string(raw_url: Any) -> str:
    """
    Carefully normalize and sanitize input URL strings.
    - Handles non-string inputs safely
    - Strips leading and trailing whitespaces and unprintable characters
    - Adds default 'http://' scheme if missing for proper URI RFC component parsing
    - Never throws an uncaught exception on malformed inputs
    """
    if raw_url is None:
        return ""
    if not isinstance(raw_url, str):
        raw_url = str(raw_url)

    clean_url = raw_url.strip()
    if not clean_url:
        return ""

    # Remove null bytes or control characters
    clean_url = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", clean_url)

    # Prepend scheme if missing so urllib.parse can reliably distinguish netloc from path
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "http://" + clean_url

    return clean_url


class _SafeParsed:
    """Safe fallback container matching standard urllib.parse attributes."""
    def __init__(self, s: str, n: str, p: str, q: str, f: str) -> None:
        self.scheme = s
        self.netloc = n
        self.path = p
        self.query = q
        self.fragment = f


def _safe_parse_url(clean_url: str) -> Any:
    """
    Safely parses URL with urllib.parse.urlparse, falling back to regex
    if urllib.parse raises ValueError (e.g. invalid IPv6 bracketed hosts).
    """
    try:
        return urllib.parse.urlparse(clean_url)
    except Exception:
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)?([^/?#]*)(/[^?#]*)?(\?[^#]*)?(#.*)?$", clean_url)
        if m:
            s = (m.group(1) or "http://").rstrip(":/")
            n = m.group(2) or ""
            p = m.group(3) or ""
            q = (m.group(4) or "").lstrip("?")
            f = (m.group(5) or "").lstrip("#")
            return _SafeParsed(s, n, p, q, f)
        return _SafeParsed("http", "", clean_url, "", "")


class FeatureExtractor:
    """
    Robust, offline URL feature extractor returning standardized numeric dictionaries
    and diagnostic inspection models.
    """

    def __init__(self) -> None:
        # Enforce offline mode by disabling remote public suffix list fetching
        self.extractor = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

    def extract(self, url: Any, tld_result: Optional[Any] = None) -> Dict[str, float]:
        """
        Extract numeric feature values for machine learning inference and training.
        Guaranteed to return all defined FEATURE_NAMES with float values, even for malformed inputs.
        Optionally accepts pre-computed tld_result to eliminate duplicate extraction overhead.
        """
        clean_url = normalize_url_string(url)
        if not clean_url:
            # Return safe default zeros for empty or null URL
            return {name: 0.0 for name in FEATURE_NAMES}

        parsed = _safe_parse_url(clean_url)

        if tld_result is not None:
            extracted = tld_result
        else:
            try:
                extracted = self.extractor(clean_url)
            except Exception:
                # Fallback if tldextract fails on non-standard strings
                extracted = tldextract.ExtractResult("", "", "")

        host = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""

        url_len = len(clean_url)
        host_len = len(host)
        path_len = len(path)
        query_len = len(query)

        # Registered domain and suffix
        reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        domain_name = reg_domain or host
        suffix = (extracted.suffix or "").lower()

        # Subdomains
        subdomain_str = extracted.subdomain or ""
        subdomain_parts = [p for p in subdomain_str.split(".") if p]
        subdomain_count = len(subdomain_parts)

        # Counts of specific characters
        dot_count = clean_url.count(".")
        hyphen_count = clean_url.count("-")
        underscore_count = clean_url.count("_")
        slash_count = clean_url.count("/")
        question_count = clean_url.count("?")
        equal_count = clean_url.count("=")
        at_count = clean_url.count("@")
        amp_count = clean_url.count("&")
        percent_count = clean_url.count("%")

        # Numeric digits
        digit_count = sum(c.isdigit() for c in clean_url)
        digit_ratio = (digit_count / url_len) if url_len > 0 else 0.0

        # Special characters (characters outside alphanumeric and standard delimiters)
        special_chars = sum(1 for c in clean_url if not c.isalnum() and c not in "/:.-_?=&%#")

        # Binary indicators
        has_ip = 1.0 if is_ip_host(host) else 0.0
        has_https = 1.0 if parsed.scheme.lower() == "https" else 0.0
        has_at_flag = 1.0 if at_count > 0 else 0.0
        is_shortened = 1.0 if (domain_name.lower() in KNOWN_SHORTENERS or host.lower() in KNOWN_SHORTENERS) else 0.0
        has_abused_tld = 1.0 if suffix in HIGH_ABUSE_TLDS else 0.0
        has_double_slash_path = 1.0 if "//" in path else 0.0
        has_punycode = 1.0 if check_punycode_or_idn(host, clean_url) else 0.0

        # Suspicious keyword matching across path, query, and subdomain
        searchable_text = f"{path.lower()} {query.lower()} {subdomain_str.lower()}"
        suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in searchable_text)

        # Query parameter count
        try:
            param_count = len(urllib.parse.parse_qs(query)) if query else 0
        except Exception:
            param_count = query.count("&") + (1 if query else 0)

        # Longest alphanumeric token
        tokens = re.split(r"[/._?=&%#\-~]", clean_url)
        longest_token = max((len(t) for t in tokens if t), default=0)

        # Character entropy
        char_entropy = calculate_entropy(clean_url)

        return {
            "url_length": float(url_len),
            "hostname_length": float(host_len),
            "path_length": float(path_len),
            "query_length": float(query_len),
            "dot_count": float(dot_count),
            "hyphen_count": float(hyphen_count),
            "underscore_count": float(underscore_count),
            "slash_count": float(slash_count),
            "question_mark_count": float(question_count),
            "equal_count": float(equal_count),
            "at_count": float(at_count),
            "ampersand_count": float(amp_count),
            "percent_count": float(percent_count),
            "digit_count": float(digit_count),
            "digit_ratio": round(digit_ratio, 4),
            "special_char_count": float(special_chars),
            "has_ip_host": has_ip,
            "has_https": has_https,
            "has_at_symbol": has_at_flag,
            "subdomain_count": float(subdomain_count),
            "is_shortened": is_shortened,
            "char_entropy": char_entropy,
            "suspicious_keyword_count": float(suspicious_count),
            "has_abused_tld": has_abused_tld,
            "has_double_slash_path": has_double_slash_path,
            "has_punycode": has_punycode,
            "param_count": float(param_count),
            "fragment_length": float(len(fragment)),
            "longest_token_length": float(longest_token),
        }

    def inspect(self, url: Any) -> Dict[str, Any]:
        """
        Produce a diagnostic structural inspection with extracted features
        and actionable security flags.
        """
        clean_url = normalize_url_string(url)
        parsed = _safe_parse_url(clean_url)
        extracted = self.extractor(clean_url)
        features = self.extract(clean_url)

        host = parsed.netloc or ""
        pure_host = extract_pure_hostname(host)
        reg_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        flags: List[Dict[str, str]] = []
        if features["has_ip_host"] == 1.0:
            flags.append({
                "rule": "IP_HOST_DETECTED",
                "severity": "HIGH",
                "message": f"URL hostname '{pure_host}' is a raw IP address instead of a registered domain."
            })
            if is_private_or_loopback_ip(pure_host):
                flags.append({
                    "rule": "INTERNAL_OR_METADATA_IP_HOST",
                    "severity": "CRITICAL",
                    "message": f"URL specifies a private, loopback, or cloud metadata address ('{pure_host}')."
                })
        if features["has_at_symbol"] == 1.0:
            flags.append({
                "rule": "CREDENTIAL_AT_SYMBOL",
                "severity": "HIGH",
                "message": "URL contains '@' symbol; browsers treat preceding text as user credentials, obscuring real destination."
            })
        if features["has_punycode"] == 1.0:
            flags.append({
                "rule": "PUNYCODE_HOMOGRAPH",
                "severity": "HIGH",
                "message": "Hostname contains Punycode ('xn--') or Unicode characters, frequently utilized in character spoofing attacks."
            })
        if features["is_shortened"] == 1.0:
            flags.append({
                "rule": "LINK_SHORTENER",
                "severity": "MEDIUM",
                "message": f"URL uses a known shortener service ({pure_host}), concealing the ultimate destination URL."
            })
        if features["has_abused_tld"] == 1.0:
            flags.append({
                "rule": "HIGH_ABUSE_TLD",
                "severity": "MEDIUM",
                "message": f"URL uses top-level domain '.{extracted.suffix}', known for elevated phishing abuse rates."
            })
        if features["subdomain_count"] >= 3:
            flags.append({
                "rule": "EXCESSIVE_SUBDOMAINS",
                "severity": "MEDIUM",
                "message": f"Host contains {int(features['subdomain_count'])} subdomains, common in brand spoofing techniques."
            })
        if features["has_double_slash_path"] == 1.0:
            flags.append({
                "rule": "DOUBLE_SLASH_REDIRECT",
                "severity": "MEDIUM",
                "message": "Path contains '//' which can be exploited for open redirect attacks."
            })
        if features["suspicious_keyword_count"] >= 2:
            flags.append({
                "rule": "SUSPICIOUS_LURE_KEYWORDS",
                "severity": "HIGH",
                "message": f"Detected {int(features['suspicious_keyword_count'])} keywords characteristic of credential harvesting."
            })
        elif features["suspicious_keyword_count"] == 1:
            flags.append({
                "rule": "SUSPICIOUS_KEYWORD",
                "severity": "LOW",
                "message": "URL contains an authentication or security keyword in path or query."
            })
        if features["char_entropy"] > 4.6:
            flags.append({
                "rule": "HIGH_ENTROPY",
                "severity": "MEDIUM",
                "message": f"Elevated character entropy ({features['char_entropy']:.2f}) indicates potential algorithmic randomness."
            })

        return {
            "input_url": str(url) if url is not None else "",
            "normalized_url": clean_url,
            "components": {
                "scheme": parsed.scheme,
                "netloc": host,
                "domain": reg_domain,
                "subdomain": extracted.subdomain,
                "suffix": extracted.suffix,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
            },
            "features": features,
            "flags": flags,
        }


# Convenience singleton
_DEFAULT_EXTRACTOR = FeatureExtractor()


def extract_url_features(url: Any) -> Dict[str, float]:
    """Top-level convenience function to extract features for a single URL."""
    return _DEFAULT_EXTRACTOR.extract(url)


def inspect_url(url: Any) -> Dict[str, Any]:
    """Top-level convenience function to inspect a URL and return features and flags."""
    return _DEFAULT_EXTRACTOR.inspect(url)
