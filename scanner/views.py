import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .checks.heuristics import check_heuristics
from .checks.safebrowsing import check_safe_browsing
from .checks.tls import check_tls
from .models import URL, Scan
from .scoring import compute_score
from .utils import normalize_url

# Serve the single page frontend
def index(request):
    return render(request, "scanner/home.html")


@csrf_exempt
@require_http_methods(["GET", "POST"])
def scan_url(request):
    if request.method == "GET":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)
    
 # Validate and normalise before running any checks
    raw_url = payload.get("url")
    try:
        normalized = normalize_url(raw_url)
    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=400)
    
 # Reuse existing URL records where possible
    url_obj, _ = URL.objects.get_or_create(canonical_url=normalized)

# Run all checks independently
    tls = check_tls(normalized)
    sb = check_safe_browsing(normalized)
    heur = check_heuristics(normalized)

    checks = {
        "normalized": True,
        "tls": tls.__dict__,
        "safe_browsing": sb.__dict__,
        "heuristics": heur.__dict__,
    }
    
# Combine signals into a final score and state
    result = compute_score(checks)

    scan = Scan.objects.create(
        url=url_obj,
        score=result.score,
        risk_level=result.risk,
        confidence=result.confidence,
        state=result.state,
        checks=checks,
    )

    return JsonResponse(
        {
            "scan_id": scan.id,
            "url": normalized,
            "score": result.score,
            "state": result.state,
            "reasons": result.reasons,
            "details": {
                "risk_level": result.risk,
                "confidence": result.confidence,
                "checks": checks,
            },
        }
    )
