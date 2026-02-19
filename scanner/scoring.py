from dataclasses import dataclass
from typing import Any, Dict


# Final output used by the API and UI
@dataclass(frozen=True)
class ScoreResult:
    score: int
    risk: str
    confidence: str
    state: str
    reasons: Dict[str, Any]


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


# Escalate risk but never downgrade it
def max_risk(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


# Confidence can only increase not decrease
def max_confidence(current: str, new: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return new if order.get(new, 0) > order.get(current, 0) else current


# Keep score ranges consistent with the final state
def clamp_score_for_state(score: int, state: str) -> int:
    score = clamp(score)
    if state == "UNSAFE":
        return clamp(score, 0, 20)
    if state == "BE_CAREFUL":
        return clamp(score, 35, 69)
    return clamp(score, 70, 100)


# Start optimistic and reduce based on evidence
def compute_score(checks: Dict[str, Any]) -> ScoreResult:
    score = 100
    risk = "low"
    confidence = "low"
    reasons: Dict[str, Any] = {}

    tls = checks.get("tls") or {}
    sb = checks.get("safe_browsing") or {}
    op = checks.get("openphish") or {}   # <-- ADD
    heur = checks.get("heuristics") or {}

    sb_status = sb.get("status")
    op_status = op.get("status")         # <-- ADD

    # ---- Hard UNSAFE signals (multi-source) ----
    if sb_status == "flagged":
        threats = sb.get("threats") or sb.get("matches") or []
        text = " ".join(str(t) for t in threats).upper()

        if "MALWARE" in text:
            score = 5
            reasons["safe_browsing"] = "Flagged by Google Safe Browsing (malware)."
        elif "SOCIAL_ENGINEERING" in text or "PHISH" in text:
            score = 8
            reasons["safe_browsing"] = "Flagged by Google Safe Browsing (phishing)."
        elif "UNWANTED" in text:
            score = 12
            reasons["safe_browsing"] = "Flagged by Google Safe Browsing (unwanted software)."
        else:
            score = 10
            reasons["safe_browsing"] = "Flagged by Google Safe Browsing."

        risk = "high"
        confidence = "high"

    elif op_status == "listed":
        # OpenPhish overrides like Safe Browsing does (backup intel source)
        score = 8
        reasons["openphish"] = "Listed in OpenPhish feed."
        risk = "high"
        confidence = "high"

    else:
        # Availability affects confidence slightly
        if sb_status == "unavailable":
            confidence = max_confidence(confidence, "medium")
        if op_status == "unavailable":
            confidence = max_confidence(confidence, "medium")

    tls_ok = bool(tls.get("ok"))
    tls_expired = bool(tls.get("expired"))
    days_to_expiry = tls.get("days_to_expiry")

    # TLS only affects the score if no hard UNSAFE source fired
    hard_unsafe = (sb_status == "flagged") or (op_status == "listed")
    if not hard_unsafe:
        if not tls_ok:
            score -= 30
            risk = max_risk(risk, "medium")
            reasons["tls"] = "TLS check not OK."

        if tls_expired:
            score = min(score, 20)
            risk = "high"
            confidence = max_confidence(confidence, "medium")
            reasons["tls_expired"] = "TLS certificate expired."

        if isinstance(days_to_expiry, int) and days_to_expiry < 14 and not tls_expired:
            score -= 10
            risk = max_risk(risk, "medium")
            reasons["tls_expiry_soon"] = f"TLS expires soon ({days_to_expiry} days)."

    heur_delta = heur.get("score_delta")
    if isinstance(heur_delta, int) and not hard_unsafe:
        score += heur_delta

    # Final user state
    heur_suspicious = bool(heur.get("suspicious"))
    if heur_suspicious:
        risk = max_risk(risk, "medium")
        reasons["heuristics"] = heur.get("reasons") or ["Heuristic indicators triggered."]

    if hard_unsafe:
        state = "UNSAFE"
    else:
        tls_problem = (not tls_ok) or tls_expired or (
            isinstance(days_to_expiry, int) and days_to_expiry < 14
        )
        if tls_problem or heur_suspicious:
            state = "BE_CAREFUL"
        else:
            state = "SAFE"

    score = clamp_score_for_state(int(score), state)

    return ScoreResult(
        score=score,
        risk=risk,
        confidence=confidence,
        state=state,
        reasons=reasons,
    )
