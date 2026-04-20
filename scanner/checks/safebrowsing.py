from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import requests
from django.conf import settings


# Result from Google Safe Browsing
@dataclass
class SafeBrowsingResult:
    status: str
    threats: list[str]
    error: Optional[str] = None


def check_safe_browsing(url: str, timeout: float = 4.0) -> SafeBrowsingResult:
    api_key = getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", None)
    if not api_key:
        return SafeBrowsingResult(status="unavailable", threats=[], error="API key missing")

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": api_key}

# Request payload sent to Google Safe Browsing
    payload = {
        "client": {"clientId": "websense", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

# If the API fails, the rest of the scan should still continue
    try:
        r = requests.post(endpoint, params=params, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return SafeBrowsingResult(status="unavailable", threats=[], error=str(e))

    matches = data.get("matches", [])
    if not matches:
        return SafeBrowsingResult(status="clean", threats=[])

    # Keep only unique threat types
    threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    return SafeBrowsingResult(status="flagged", threats=threat_types)