from __future__ import annotations

import socket 
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

@dataclass
class TLSCheckResult:
    ok: bool
    expired: bool
    days_to_expiry: Optional[int]
    not_after: Optional[str]
    error: Optional[str] = None

def check_tls(url: str, timeout: float = 4.0) -> TLSCheckResult:
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return TLSCheckResult(ok=False, expired=False, days_to_expiry=None, error="Missing hostname" )
    
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLError as e:
        return TLSCheckResult(ok=False, expired=False, days_to_expiry=None, not_after=None, error=f"TLS error: {e.__class__.__name__}")
    except (socket.timeout, TimeoutError):
        return TLSCheckResult(ok=False, expired=False, days_to_expiry=None, not_after=None, error="TLS connection timed out")
    except OSError as e:
        return TLSCheckResult(ok=False, expired=False, days_to_expiry=None, not_after=None, error=f"Connection error: {e.__class__.__name__}")
    
    not_after_raw = cert.get("notAfter")
    if not not_after_raw:
        return TLSCheckResult(ok=False, expired=False, days_to_expiry=None, not_after=None, error="Certificate missing notAfter")
    
    try:
        expires = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return TLSCheckResult(ok=False, expired=False, days_to_expiry=None, not_after=not_after_raw, error="Could not parse expiry")
    
    now = datetime.now(timezone.utc)
    expired = expires <= now
    days = int((expires - now).total_seconds() // 86400)

    return TLSCheckResult(
        ok=not expired,
        expired=expired,
        days_to_expiry=days,
        not_after=expires.isoformat(),
        error=None,
    )
    
    

    
