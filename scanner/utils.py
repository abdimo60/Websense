from __future__ import annotations

import ipaddress
import re 
from urllib.parse import urlsplit, urlunsplit

# Detect invalid characters
_BAD_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\s]")

# Clean and validate URL before scanning
def normalize_url(raw: str) -> str:
    """Validate and canonicalise a user-supplied URL for scanning."""

    if raw is None:
        raise ValueError("Missing URL")
    
    s= raw.strip()
    if not s:
        raise ValueError("URL is empty")
    
    if _BAD_CHARS_RE.search(s):
        raise ValueError("URL contains invalid whitespace/control characters")
    
# Fix slashes
    s = s.replace("\\","/")

# Add https if missing
    if "://" not in s:
        s = "https://" + s
    
    parts = urlsplit(s)

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed")
    
# Block usernames/passwords in URL
    if parts.username or parts.password:
        raise ValueError("URLs with embedded credentials are not allowed")
    
    if not parts.netloc:
        raise ValueError("Invalid URL (missing hostname)")
    
    host = parts.hostname
    if not host:
        raise ValueError("Invalid hostname")
    
    host_lc = host.lower()

# Allow IP or valid domain
    if host_lc != "localhost":
        if _is_ip(host_lc):
            pass
        else:
            if not _looks_like_domain(host_lc):
                raise ValueError("Hostname does not look valid")
            
    port = parts.port
    keep_port = ""
    if port is not None:
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            keep_port = f":{port}"
    
    path = parts.path or "/"

# Fragments are ignored for scanning
    fragment = ""

    query = parts.query

    netloc = f"{host_lc}{keep_port}"

    normalized = urlunsplit((scheme, netloc, path, query, fragment))

    if len(normalized) > 2048:
        raise ValueError("URL is too long")
    
    return normalized

# Check for literal IP addresses
def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

# Basic sanity checks for domain names
def _looks_like_domain(host: str) -> bool:
    if "." not in host:
        return False
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return False

    labels = host.split(".")
    if any(not label for label in labels):
        return False

    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return False
        if len(label) > 63:
            return False

    return True
