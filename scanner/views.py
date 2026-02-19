import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .checks.heuristics import check_heuristics
from .checks.safebrowsing import check_safe_browsing
from .checks.tls import check_tls
from .checks.openphish import check_openphish 
from .models import URL, Scan
from .scoring import compute_score
from .utils import normalize_url


# Serve the single page frontend
def index(request):
    return render(request, "scanner/home.html")


def _response(
    *,
    state: str,
    explanation: str,
    url: str | None = None,
    score: int | None = None,
    reasons: dict | None = None,
    checks: dict | None = None,
    scan_id: int | None = None,
    error: str | None = None,
    status: int = 200,
):
    payload = {
        "state": state,
        "explanation": explanation,
        "url": url,
        "score": score,
        "reasons": reasons or {},
        "checks": checks or {},
        "scan_id": scan_id,
    }
    if error:
        payload["error"] = error
    return JsonResponse(payload, status=status)


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

    checks = {"normalized": False}

    # Parse JSON safely
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

    # Normalize URL safely
    try:
        normalized = normalize_url(raw_url)
        checks["normalized"] = True
    except ValueError as e:
        return _response(
            state="BE_CAREFUL",
            explanation=str(e),
            error="invalid_url",
            status=400,
        )

    # Get or create URL record
    url_obj = None
    try:
        url_obj, _ = URL.objects.get_or_create(canonical_url=normalized)
    except Exception as e:
        checks["db"] = {"ok": False, "error": str(e)[:160]}

    # Run checks safely
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

    # Compute score
    try:
        result = compute_score(checks)
    except Exception as e:
        return _response(
            state="BE_CAREFUL",
            explanation="Scan failed safely due to an internal error.",
            url=normalized,
            checks=checks,
            error=str(e)[:160],
            status=200,
        )

    # Save Scan record
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

    # Explanation
    if result.state == "UNSAFE":
        explanation = "This looks unsafe based on one or more strong risk signals."
    elif result.state == "BE_CAREFUL":
        explanation = "Some risk signals were detected. Proceed carefully."
    else:
        explanation = "No strong risk signals detected."

    return _response(
        state=result.state,
        explanation=explanation,
        url=normalized,
        score=result.score,
        reasons=result.reasons,
        checks=checks,
        scan_id=scan_id,
        status=200,
    )
