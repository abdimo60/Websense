from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class ScoreResult:
    score: int
    risk: str
    confidence: str
    reasons: Dict[str, Any]


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


def max_risk(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


def max_confidence(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


def compute_score(checks: Dict[str, Any]) -> ScoreResult:
    score = 100
    risk = "low"
    confidence = "low"
    reasons: Dict[str, Any] = {}

    tls = checks.get("tls") or {}
    sb = checks.get("safe_browsing") or {}
    heur = checks.get("heuristics") or {}

    sb_status = sb.get("status")
    if sb_status == "flagged":
        score = min(score, 10)
        risk = "high"
        confidence = "high"
        reasons["safe_browsing"] = "Flagged by Google Safe Browsing."
    elif sb_status == "unavailable":
        confidence = max_confidence(confidence, "medium")

    tls_ok = bool(tls.get("ok"))
    tls_expired = bool(tls.get("expired"))
    days_to_expiry = tls.get("days_to_expiry")

    if sb_status != "flagged":
        if not tls_ok:
            score -= 30
            risk = max_risk(risk, "medium")
            confidence = max_confidence(confidence, "low")
            reasons["tls"] = "TLS check not OK."

        if tls_expired:
            score = min(score, 20)
            risk = "high"
            confidence = max_confidence(confidence, "medium")
            reasons["tls_expired"] = "TLS certificate expired."

        if isinstance(days_to_expiry, int) and days_to_expiry < 14 and not tls_expired:
            score -= 10
            risk = max_risk(risk, "medium")
            confidence = max_confidence(confidence, "low")
            reasons["tls_expiry_soon"] = f"TLS expires soon ({days_to_expiry} days)."

    heur_delta = heur.get("score_delta")
    if isinstance(heur_delta, int):
        score += heur_delta

    if heur.get("suspicious"):
        risk = max_risk(risk, "medium")
        reasons["heuristics"] = heur.get("reasons") or ["Heuristic indicators triggered."]

    score = clamp(int(score))
    return ScoreResult(score=score, risk=risk, confidence=confidence, reasons=reasons)
