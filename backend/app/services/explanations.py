"""
Cybersecurity Explainability and Human-Readable Analysis Engine.

Translates numeric and structural feature observations into plain-English,
actionable security findings for analysts and end-users.
Explicitly clarifies that HTTPS transport does not imply website authenticity,
and reinforces that all predictions are probabilistic defensive assessments.
"""

from __future__ import annotations
from typing import Any, Dict, List
from backend.app.schemas.scan import ExplanationItem, FeatureItem
from backend.app.ml.features import FEATURE_METADATA

HTTPS_ANALYSIS_TEXT = (
    "HTTPS indicates that network transport between the browser and the web server is encrypted "
    "using TLS/SSL. However, threat actors routinely obtain free, automated TLS certificates "
    "(such as via Let's Encrypt or zero-cost CAs) for disposable phishing domains. "
    "Therefore, the presence of HTTPS establishes encrypted transmission, but DOES NOT guarantee "
    "domain authenticity, business legitimacy, or safety."
)

SAFETY_DISCLAIMER_TEXT = (
    "Automated Defensive Assessment Notice: This analysis is an automated evaluation based on "
    "offline lexical, structural, and machine learning heuristics. It is a risk estimation, "
    "NEVER a guarantee that a website is safe. Attackers frequently compromise legitimate websites "
    "or use deceptive redirects. Never submit credentials or confidential data without out-of-band verification."
)


class ExplanationEngine:
    """Generates structured, human-readable explanations from extracted URL features."""

    @classmethod
    def generate_explanations(
        cls,
        features: Dict[str, float],
        components: Dict[str, str],
    ) -> List[ExplanationItem]:
        """
        Analyzes URL features and extracts actionable security findings explaining
        why a URL is considered risky or low-risk.
        """
        findings: List[ExplanationItem] = []

        host = components.get("netloc", "")
        domain = components.get("domain", "")
        suffix = components.get("suffix", "")
        path = components.get("path", "")

        # 1. IP Hostname Indicator
        if features.get("has_ip_host", 0.0) == 1.0:
            findings.append(ExplanationItem(
                rule="RAW_IP_HOST",
                title="Direct IP Address Hostname Detected",
                severity="CRITICAL",
                message=f"The URL specifies a direct IP address ('{host}') rather than a registered domain name.",
                threat_context="Legitimate public organizations and services use registered domain names. Phishing campaigns frequently deploy on direct IP addresses to avoid domain registration records or DNS blacklists."
            ))

        # 2. Punycode / Homograph Attack Indicator
        if features.get("has_punycode", 0.0) == 1.0:
            findings.append(ExplanationItem(
                rule="PUNYCODE_HOMOGRAPH",
                title="Punycode / IDN Homograph Sequence Observed",
                severity="HIGH",
                message="Hostname contains 'xn--', indicating an Internationalized Domain Name (IDN).",
                threat_context="Attackers exploit lookalike Unicode characters (e.g. Cyrillic 'а' replacing Latin 'a') to visually spoof brand domains while actually resolving to attacker-controlled infrastructure."
            ))

        # 3. Credential '@' Symbol in URL
        if features.get("has_at_symbol", 0.0) == 1.0 or features.get("at_count", 0.0) > 0:
            findings.append(ExplanationItem(
                rule="CREDENTIAL_USERINFO_DELIMITER",
                title="Deceptive '@' Character Present",
                severity="HIGH",
                message="The URL contains an '@' character within the authority segment.",
                threat_context="Standard RFC specifications interpret text preceding '@' as user credentials, not the hostname. Attackers use this to display a fake brand name before the '@' while directing victims to the domain after the '@'."
            ))

        # 4. Known URL Shortener
        if features.get("is_shortened", 0.0) == 1.0:
            findings.append(ExplanationItem(
                rule="LINK_SHORTENER_OBSCURATION",
                title="URL Shortening Service Detected",
                severity="MEDIUM",
                message=f"The domain '{host}' is a known URL shortening or redirection proxy.",
                threat_context="Shorteners conceal the true destination hostname, preventing users and basic email filters from inspecting the landing site before click-through."
            ))

        # 5. High-Abuse Top-Level Domain
        if features.get("has_abused_tld", 0.0) == 1.0:
            findings.append(ExplanationItem(
                rule="HIGH_ABUSE_TLD",
                title=f"Elevated-Abuse TLD (.{suffix}) Identified",
                severity="MEDIUM",
                message=f"The URL uses top-level domain '.{suffix}', which has historically high concentrations of disposable phishing campaigns.",
                threat_context="Free or heavily discounted TLDs attract malicious actors who register throwaway domains in bulk for short-lived phishing lures."
            ))

        # 6. Excessive Subdomain Layering
        sub_count = int(features.get("subdomain_count", 0.0))
        if sub_count >= 3:
            findings.append(ExplanationItem(
                rule="EXCESSIVE_SUBDOMAINS",
                title=f"Excessive Subdomain Stacking ({sub_count} Subdomains)",
                severity="HIGH",
                message=f"The host contains {sub_count} nested subdomain levels (e.g. '{components.get('subdomain', '')}').",
                threat_context="Attackers chain subdomains to simulate authentic URLs on mobile viewports (e.g. 'paypal.com.account-update.attacker.com') where the end of the URL is truncated."
            ))

        # 7. Suspicious Credential Lure Keywords
        kw_count = int(features.get("suspicious_keyword_count", 0.0))
        if kw_count >= 2:
            findings.append(ExplanationItem(
                rule="MULTIPLE_PHISHING_LURE_TOKENS",
                title=f"Multiple Credential Harvesting Keywords Detected ({kw_count})",
                severity="HIGH",
                message=f"The path and query strings contain {kw_count} keywords commonly associated with urgent account or authentication lures.",
                threat_context="Keywords like 'login', 'verify', 'update', 'banking', and 'account' are classic indicators of social engineering campaigns seeking to capture user login credentials."
            ))
        elif kw_count == 1:
            findings.append(ExplanationItem(
                rule="SINGLE_PHISHING_LURE_TOKEN",
                title="Authentication Keyword Present",
                severity="LOW",
                message="Detected an authentication or verification keyword in the URL path/query.",
                threat_context="Authentication keywords can be benign on authentic sites, but heighten risk when combined with anomalous domain structures."
            ))

        # 8. Double Slash Redirect Construction
        if features.get("has_double_slash_path", 0.0) == 1.0:
            findings.append(ExplanationItem(
                rule="DOUBLE_SLASH_REDIRECT",
                title="Double Forward Slash in Path",
                severity="MEDIUM",
                message="The URL path contains '//' outside the protocol separator.",
                threat_context="Double slashes inside path parameters frequently indicate open-redirect vulnerabilities where a trusted site is manipulated into redirecting victims to a phishing page."
            ))

        # 9. High Character Entropy
        entropy = features.get("char_entropy", 0.0)
        if entropy > 4.6:
            findings.append(ExplanationItem(
                rule="ELEVATED_CHARACTER_ENTROPY",
                title=f"High Character Randomness (Entropy: {entropy:.2f})",
                severity="MEDIUM",
                message=f"Character Shannon entropy ({entropy:.2f}) is noticeably higher than typical natural language URLs.",
                threat_context="High entropy suggests algorithmically generated domains (DGA), randomized session tracking, or base64-encoded credential payloads embedded in URL strings."
            ))

        # 10. Baseline finding if no critical anomalies observed
        if not findings:
            findings.append(ExplanationItem(
                rule="STANDARD_LEXICAL_STRUCTURE",
                title="Standard Lexical and Structural Characteristics",
                severity="INFO",
                message="No overt lexical anomalies, IP hostnames, or deceptive URL masking techniques were identified in the static string.",
                threat_context="The URL exhibits standard naming conventions, character distribution, and structural conventions consistent with typical web resources."
            ))

        return findings

    @classmethod
    def compile_feature_details(cls, features: Dict[str, float]) -> List[FeatureItem]:
        """
        Enriches numeric feature dictionary with descriptive metadata, threat rationales,
        and individual flag evaluations.
        """
        details: List[FeatureItem] = []
        for name, value in features.items():
            meta = FEATURE_METADATA.get(name, {})
            desc = meta.get("description", "Lexical feature measurement.")
            rationale = meta.get("rationale", "Contributes to statistical URL evaluation.")

            is_flagged = False
            flag_reason = None

            if name == "has_ip_host" and value == 1.0:
                is_flagged = True
                flag_reason = "Host is a numeric IP address."
            elif name == "has_at_symbol" and value == 1.0:
                is_flagged = True
                flag_reason = "Contains '@' userinfo credential trick."
            elif name == "has_punycode" and value == 1.0:
                is_flagged = True
                flag_reason = "Contains 'xn--' punycode homograph string."
            elif name == "has_abused_tld" and value == 1.0:
                is_flagged = True
                flag_reason = "Uses high-abuse top level domain."
            elif name == "is_shortened" and value == 1.0:
                is_flagged = True
                flag_reason = "Domain is a known link shortener."
            elif name == "subdomain_count" and value >= 3:
                is_flagged = True
                flag_reason = f"Contains {int(value)} stacked subdomains."
            elif name == "suspicious_keyword_count" and value >= 2:
                is_flagged = True
                flag_reason = f"Contains {int(value)} credential lure keywords."
            elif name == "has_double_slash_path" and value == 1.0:
                is_flagged = True
                flag_reason = "Contains '//' open redirect pattern."
            elif name == "char_entropy" and value > 4.6:
                is_flagged = True
                flag_reason = f"High entropy ({value:.2f}) indicates randomness or encoding."

            details.append(FeatureItem(
                name=name,
                value=round(float(value), 4),
                description=desc,
                threat_rationale=rationale,
                is_flagged=is_flagged,
                flag_reason=flag_reason,
            ))

        return details
