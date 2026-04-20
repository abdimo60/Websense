from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse
import ipaddress
import re


# Output from URL heuristics
@dataclass
class HeuristicResult:
    suspicious: bool
    reasons: List[str]
    score_delta: int
    triggered_count: int
    url_length: int
    subdomain_depth: int
    ip_host: bool
    punycode_detected: bool
    numeric_ip_url: bool
    suspicious_keywords_detected: bool
    brand_spoof_detected: bool


# Count subdomains in host
def _subdomain_depth(host: str) -> int:
    if not host:
        return 0
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


# Check if host is an IP address
def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Detect punycode in hostname
def _has_punycode(host: str) -> bool:
    if not host:
        return False
    return "xn--" in host.lower()


# Detect numeric IP URLs
def _has_numeric_ip_url(url: str) -> bool:
    return bool(re.match(r"^https?://\d+\.\d+\.\d+\.\d+", url.strip(), re.IGNORECASE))


# Split URL into words for keyword checks
def _tokenise_url_parts(host: str, path: str) -> List[str]:
    combined = f"{host} {path}".lower()
    return [t for t in re.split(r"[^a-z0-9]+", combined) if t]


# Check for common phishing keywords
def _has_suspicious_keywords(host: str, path: str) -> bool:
    tokens = _tokenise_url_parts(host, path)

    keywords = {
        "login", "signin", "verify", "secure",
        "update", "account", "password",
        "reset", "confirm", "auth",
        "bank", "payment", "billing"
    }

    # Require at least 2 keyword matches
    return sum(1 for t in tokens if t in keywords) >= 2


# Check for brand spoofing patterns
def _has_brand_spoof_pattern(host: str) -> bool:
    if not host:
        return False

    brands = {
        "paypal", "google", "microsoft", "apple",
        "amazon", "facebook", "instagram", "linkedin"
    }

    parts = [p for p in host.lower().split(".") if p]
    if len(parts) < 3:
        return False

    left = parts[:-2]
    joined = ".".join(left)

    suspicious_terms = {"login", "secure", "verify", "update", "account"}

    brand_present = any(b in left or b in joined for b in brands)
    suspicious_present = any(term in joined for term in suspicious_terms)

    return brand_present and suspicious_present


# Main URL heuristic check
def check_heuristics(
    url: str,
    url_len_threshold: int = 100,
    subdomain_threshold: int = 3,
) -> HeuristicResult:

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""

    url_length = len(url)
    subdomain_depth = _subdomain_depth(host)
    ip_host = _is_ip_host(host)
    punycode_detected = _has_punycode(host)
    numeric_ip_url = _has_numeric_ip_url(url)
    suspicious_keywords_detected = _has_suspicious_keywords(host, path)
    brand_spoof_detected = _has_brand_spoof_pattern(host)

    reasons: List[str] = []
    score_delta = 0
    suspicious = False
    triggered_count = 0

    # Long URLs can be suspicious
    if url_length >= url_len_threshold:
        suspicious = True
        triggered_count += 1
        reasons.append(f"Long URL ({url_length} chars).")
        score_delta -= 10

    # Too many subdomains can be suspicious
    if subdomain_depth >= subdomain_threshold:
        suspicious = True
        triggered_count += 1
        reasons.append(f"High subdomain depth ({subdomain_depth}).")
        score_delta -= 15

    # IP address instead of normal domain
    if ip_host or numeric_ip_url:
        suspicious = True
        triggered_count += 1
        reasons.append("Uses a numeric IP instead of a normal domain.")
        score_delta -= 20

    # Punycode may indicate lookalike domains
    if punycode_detected:
        suspicious = True
        triggered_count += 1
        reasons.append("Uses punycode (possible lookalike domain).")
        score_delta -= 20

    # Login style phishing keywords
    if suspicious_keywords_detected:
        suspicious = True
        triggered_count += 1
        reasons.append("Contains multiple suspicious login-related keywords.")
        score_delta -= 15

    # Spoofed brand-style structure
    if brand_spoof_detected:
        suspicious = True
        triggered_count += 1
        reasons.append("Domain structure looks like a spoofed brand.")
        score_delta -= 20

    return HeuristicResult(
        suspicious=suspicious,
        reasons=reasons,
        score_delta=score_delta,
        triggered_count=triggered_count,
        url_length=url_length,
        subdomain_depth=subdomain_depth,
        ip_host=ip_host,
        punycode_detected=punycode_detected,
        numeric_ip_url=numeric_ip_url,
        suspicious_keywords_detected=suspicious_keywords_detected,
        brand_spoof_detected=brand_spoof_detected,
    )