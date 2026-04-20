from dataclasses import dataclass
from typing import Any, Dict


# Final score data returned to the API and UI
@dataclass(frozen=True)
class ScoreResult:
    score: int
    risk: str
    confidence: str
    state: str
    reasons: Dict[str, Any]


# Keep score between 0–100
def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


# Raise risk only if the new level is higher
def max_risk(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


# Raise confidence only if the new level is higher
def max_confidence(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


# Force the score to stay inside the range for the final state
def clamp_score_for_state(score: int, state: str) -> int:
    score = clamp(score)

    if state == "UNSAFE":
        return clamp(score, 0, 20)

    if state == "BE_CAREFUL":
        return clamp(score, 21, 60)

    return clamp(score, 61, 100)


# Set confidence from the final result and hard override checks
def confidence_from_result(score: int, state: str, hard_unsafe: bool) -> str:
    if hard_unsafe:
        return "high"

    if state == "SAFE":
        return "high" if score >= 85 else "medium"

    if state == "BE_CAREFUL":
        return "high" if score <= 40 else "medium"

    return "high"


# Main scoring function that combines all scan checks
def compute_score(checks: Dict[str, Any]) -> ScoreResult:
    score = 100
    risk = "low"
    confidence = "low"
    reasons: Dict[str, Any] = {}

    tls = checks.get("tls") or {}
    sb = checks.get("safe_browsing") or {}
    op = checks.get("openphish") or {}
    heur = checks.get("heuristics") or {}

    sb_status = sb.get("status")
    op_status = op.get("status")

# Trusted blacklist hits immediately force an unsafe result
    if sb_status == "flagged":
        score = 8
        reasons["safe_browsing"] = "Flagged by Google Safe Browsing."
        risk = "high"
        confidence = "high"

    elif op_status == "listed":
        score = 8
        reasons["openphish"] = "Found in OpenPhish feed."
        risk = "high"
        confidence = "high"

    tls_ok = bool(tls.get("ok"))
    tls_expired = bool(tls.get("expired"))
    days_to_expiry = tls.get("days_to_expiry")

# Detect whether the URL is using HTTPS
    scheme = str(tls.get("scheme") or "").lower()
    if scheme:
        uses_https = scheme == "https"
    else:
        uses_https = bool(tls_ok)

    hard_unsafe = (sb_status == "flagged") or (op_status == "listed")

# Apply TLS and transport penalties if no hard override was triggered
    if not hard_unsafe:
        if not uses_https:
            score -= 20
            risk = max_risk(risk, "medium")
            reasons["http_only"] = "This website does not use HTTPS encryption."

        if not tls_ok:
            score -= 15
            risk = max_risk(risk, "medium")
            reasons["tls"] = "Not securely configured."

        if tls_expired:
            score -= 35
            risk = "high"
            reasons["tls_expired"] = "Certificate has expired."

        if isinstance(days_to_expiry, int) and days_to_expiry < 14 and not tls_expired:
            score -= 10
            reasons["tls_expiry_soon"] = "Certificate expires soon."

 # Extract heuristic results
    heur_delta = heur.get("score_delta")
    heur_suspicious = bool(heur.get("suspicious"))
    heur_reasons = heur.get("reasons") or []
    heur_triggered_count = int(heur.get("triggered_count") or 0)

    brand_spoof_detected = bool(heur.get("brand_spoof_detected"))
    suspicious_keywords_detected = bool(heur.get("suspicious_keywords_detected"))
    numeric_ip_url = bool(heur.get("numeric_ip_url"))
    punycode_detected = bool(heur.get("punycode_detected"))

 # Apply heuristic score adjustment
    if isinstance(heur_delta, int) and not hard_unsafe:
        score += heur_delta

    if heur_suspicious:
        risk = max_risk(risk, "medium")
        reasons["heuristics"] = heur_reasons

        if heur_triggered_count >= 2:
            risk = max_risk(risk, "high")

# Extra penalties for stronger suspicious combinations
    if not hard_unsafe:
        if brand_spoof_detected and suspicious_keywords_detected:
            score -= 10
            risk = max_risk(risk, "high")

        if numeric_ip_url and suspicious_keywords_detected:
            score -= 10
            risk = max_risk(risk, "high")

        if punycode_detected and suspicious_keywords_detected:
            score -= 10
            risk = max_risk(risk, "high")

# Convert the final score into a user facing state
    if hard_unsafe:
        state = "UNSAFE"
    else:
        if score <= 20:
            state = "UNSAFE"
        elif score <= 60:
            state = "BE_CAREFUL"
        else:
            state = "SAFE"

        if state == "SAFE" and not uses_https:
            state = "BE_CAREFUL"

        if state == "SAFE" and (not tls_ok) and heur_suspicious:
            state = "BE_CAREFUL"

        if heur_triggered_count >= 3 and state == "BE_CAREFUL":
            state = "UNSAFE"

    score = clamp_score_for_state(int(score), state)
    confidence = confidence_from_result(score, state, hard_unsafe)

    return ScoreResult(
        score=score,
        risk=risk,
        confidence=confidence,
        state=state,
        reasons=reasons,
    )