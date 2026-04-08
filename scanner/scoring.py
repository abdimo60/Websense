from dataclasses import dataclass
from typing import Any, Dict


# Final output returned to API/UI
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


# Increase risk but never reduce it
def max_risk(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


# Same idea for confidence
def max_confidence(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


# Make sure score matches the final state
def clamp_score_for_state(score: int, state: str) -> int:
    score = clamp(score)

    if state == "UNSAFE":
        return clamp(score, 0, 20)

    if state == "BE_CAREFUL":
        return clamp(score, 21, 60)

    return clamp(score, 61, 100)


# Set confidence level based on result strength
def confidence_from_result(score: int, state: str, hard_unsafe: bool) -> str:
    if hard_unsafe:
        return "high"

    if state == "SAFE":
        return "high" if score >= 85 else "medium"

    if state == "BE_CAREFUL":
        return "high" if score <= 40 else "medium"

    return "high"


# Main scoring logic
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

    # Hard overrides (high confidence)
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

    hard_unsafe = (sb_status == "flagged") or (op_status == "listed")

    # TLS penalties
    if not hard_unsafe:

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

    # Heuristics
    heur_delta = heur.get("score_delta")
    heur_suspicious = bool(heur.get("suspicious"))
    heur_reasons = heur.get("reasons") or []
    heur_triggered_count = int(heur.get("triggered_count") or 0)

    if isinstance(heur_delta, int) and not hard_unsafe:
        score += heur_delta

    if heur_suspicious:
        risk = max_risk(risk, "medium")
        reasons["heuristics"] = heur_reasons

        if heur_triggered_count >= 2:
            risk = max_risk(risk, "high")

    # Final classification
    if hard_unsafe:
        state = "UNSAFE"
    else:
        if score <= 20:
            state = "UNSAFE"
        elif score <= 60:
            state = "BE_CAREFUL"
        else:
            state = "SAFE"

        # Combine weak signals
        if state == "SAFE" and (not tls_ok) and heur_suspicious:
            state = "BE_CAREFUL"

        # Strong heuristic combo
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