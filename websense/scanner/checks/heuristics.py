from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse
import ipaddress


# Output from simple URL heuristics
@dataclass
class HeuristicResult:
    suspicious: bool
    reasons: List[str]
    score_delta: int
    url_length: int
    subdomain_depth: int
    ip_host: bool
    punycode_detected: bool


# Counts how many subdomains exist beyond the main domain
def _subdomain_depth(host: str) -> int:
    if not host:
        return 0
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


# Detects whether the host is a raw IP address
def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Detects punycode domains often used in homograph attacks
def _has_punycode(host: str) -> bool:
    if not host:
        return False
    return "xn--" in host.lower()


def check_heuristics(
    url: str,
    url_len_threshold: int = 120,
    subdomain_threshold: int = 4,
) -> HeuristicResult:
    parsed = urlparse(url)
    host = parsed.hostname or ""

    url_length = len(url)
    subdomain_depth = _subdomain_depth(host)
    ip_host = _is_ip_host(host)
    punycode_detected = _has_punycode(host)

    reasons: List[str] = []
    score_delta = 0
    suspicious = False

    # Long URLs are often used to hide what the link is doing
    if url_length >= url_len_threshold:
        suspicious = True
        reasons.append(f"Long URL ({url_length} chars).")
        score_delta -= 10

    # Deep subdomains are a common phishing pattern
    if subdomain_depth >= subdomain_threshold:
        suspicious = True
        reasons.append(f"High subdomain depth ({subdomain_depth}).")
        score_delta -= 10

    # Raw IP hosts are unusual for normal public-facing websites
    if ip_host:
        suspicious = True
        reasons.append("Uses an IP address instead of a normal domain name.")
        score_delta -= 15

    # Punycode can be used to imitate trusted domains
    if punycode_detected:
        suspicious = True
        reasons.append("Domain uses punycode, which can hide lookalike characters.")
        score_delta -= 15

    return HeuristicResult(
        suspicious=suspicious,
        reasons=reasons,
        score_delta=score_delta,
        url_length=url_length,
        subdomain_depth=subdomain_depth,
        ip_host=ip_host,
        punycode_detected=punycode_detected,
    )