import json
from datetime import timedelta

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .checks.heuristics import check_heuristics
from .checks.openphish import check_openphish
from .checks.safebrowsing import check_safe_browsing
from .checks.tls import check_tls
from .models import URL, Scan
from .scoring import compute_score
from .utils import normalize_url


# Serve the frontend page
def index(request):
    return render(request, "scanner/home.html")

# Build a standard JSON response
def _response(
    *,
    state: str,
    explanation: str,
    url: str | None = None,
    score: int | None = None,
    confidence: str | None = None,
    reasons: dict | None = None,
    checks: dict | None = None,
    scan_id: int | None = None,
    error: str | None = None,
    cached: bool = False,
    status: int = 200,
):
    payload = {
        "state": state,
        "explanation": explanation,
        "url": url,
        "score": score,
        "confidence": confidence,
        "reasons": reasons or {},
        "checks": checks or {},
        "scan_id": scan_id,
        "cached": cached,
    }
    if error:
        payload["error"] = error
    return JsonResponse(payload, status=status)


# Create a simple explanation for the user
def build_explanation(state: str, reasons: dict) -> str:
    if state == "UNSAFE":
        if reasons.get("safe_browsing"):
            return "This link looks unsafe because it appears in a phishing or malware database."

        if reasons.get("openphish"):
            return "This link looks unsafe because it appears in a phishing database."

        if reasons.get("tls_expired"):
            return "This link looks unsafe because the site's security certificate has expired."

        return "This looks unsafe based on one or more strong risk signals."

    elif state == "BE_CAREFUL":
        heur_reasons = reasons.get("heuristics") or []

        if heur_reasons:
            return "Some warning signs were found in the web address. Proceed carefully."

        if reasons.get("tls") or reasons.get("tls_expiry_soon"):
            return "This site may not be securely configured. Proceed carefully."

        return "Some risk signals were detected. Proceed carefully."

    else:
        return "No strong risk signals detected."

# Check if a recent scan result already exists
def _get_fresh_cached_scan(url_obj):
    cache_minutes = getattr(settings, "SCAN_CACHE_MINUTES", 60)
    cutoff = timezone.now() - timedelta(minutes=cache_minutes)

    return (
        Scan.objects
        .filter(url=url_obj, created_at__gte=cutoff)
        .order_by("-created_at")
        .first()
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def scan_url(request):
    if request.method == "GET":
        return _response(
            state="BE_CAREFUL",
            explanation="POST required.",
            error="method_not_allowed",
            status=405,
        )

    checks = {
        "normalized": False,
        "url": None,
    }

# Read request JSON safely
    try:
        payload = json.loads((request.body or b"").decode("utf-8"))
    except Exception:
        return _response(
            state="BE_CAREFUL",
            explanation="Invalid JSON body.",
            error="invalid_json",
            status=400,
        )

    raw_url = (payload.get("url") or "").strip()
    if not raw_url:
        return _response(
            state="BE_CAREFUL",
            explanation="No URL provided.",
            error="missing_url",
            status=400,
        )

# Clean and validate the URL
    try:
        normalized = normalize_url(raw_url)
        checks["normalized"] = True
        checks["url"] = normalized
    except ValueError as e:
        return _response(
            state="BE_CAREFUL",
            explanation=str(e),
            error="invalid_url",
            status=400,
        )

# Store or find the URL in the database
    url_obj = None
    try:
        url_obj, _ = URL.objects.get_or_create(canonical_url=normalized)
    except Exception as e:
        checks["db"] = {"ok": False, "error": str(e)[:160]}

# Reuse a recent scan if available
    if url_obj is not None:
        try:
            cached_scan = _get_fresh_cached_scan(url_obj)
            if cached_scan is not None:
                cached_checks = cached_scan.checks or {}
                cached_result = compute_score(cached_checks)
                explanation = build_explanation(cached_scan.state, cached_result.reasons)

                return _response(
                    state=cached_scan.state,
                    explanation=explanation,
                    url=normalized,
                    score=cached_scan.score,
                    confidence=cached_scan.confidence,
                    reasons=cached_result.reasons,
                    checks=cached_checks,
                    scan_id=cached_scan.id,
                    cached=True,
                    status=200,
                )
        except Exception as e:
            checks["cache"] = {"ok": False, "error": str(e)[:160]}

# Run each phishing check
    try:
        tls = check_tls(normalized)
        checks["tls"] = tls.__dict__
    except Exception as e:
        checks["tls"] = {"ok": False, "error": str(e)[:160]}

    try:
        sb = check_safe_browsing(normalized)
        checks["safe_browsing"] = sb.__dict__
    except Exception as e:
        checks["safe_browsing"] = {"status": "unavailable", "error": str(e)[:160]}

    try:
        op = check_openphish(normalized)
        checks["openphish"] = op.__dict__
    except Exception as e:
        checks["openphish"] = {"status": "unavailable", "error": str(e)[:160]}

    try:
        heur = check_heuristics(normalized)
        checks["heuristics"] = heur.__dict__
    except Exception as e:
        checks["heuristics"] = {"suspicious": False, "error": str(e)[:160]}

# Calculate final result
    try:
        result = compute_score(checks)
    except Exception as e:
        return _response(
            state="BE_CAREFUL",
            explanation="Scan failed safely due to an internal error.",
            url=normalized,
            checks=checks,
            error=str(e)[:160],
            cached=False,
            status=200,
        )

# Save scan result
    scan_id = None
    try:
        if url_obj is not None:
            scan = Scan.objects.create(
                url=url_obj,
                score=result.score,
                risk_level=result.risk,
                confidence=result.confidence,
                state=result.state,
                checks=checks,
            )
            scan_id = scan.id
    except Exception as e:
        checks["db_write"] = {"ok": False, "error": str(e)[:160]}

    explanation = build_explanation(result.state, result.reasons)

    return _response(
        state=result.state,
        explanation=explanation,
        url=normalized,
        score=result.score,
        confidence=result.confidence,
        reasons=result.reasons,
        checks=checks,
        scan_id=scan_id,
        cached=False,
        status=200,
    )