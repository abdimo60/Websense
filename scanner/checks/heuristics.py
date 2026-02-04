from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse

# Output from simple URL heuristics
@dataclass
class HeuristicResult:
    suspicious: bool
    reasons: List[str]
    score_delta: int
    url_length: int
    subdomain_depth: int

# Counts how many subdomains exist beyond the main domain
def _subdomain_depth(host: str) -> int:
    if not host:
        return 0
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2

def check_heuristics(url: str, url_len_threshold: int = 120, subdomain_threshold: int = 4) -> HeuristicResult:
    parsed = urlparse(url)
    host = parsed.hostname or ""

    url_length = len(url)
    subdomain_depth = _subdomain_depth(host)

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

    return HeuristicResult(
        suspicious=suspicious,
        reasons=reasons,
        score_delta=score_delta,
        url_length=url_length,
        subdomain_depth=subdomain_depth,
    )