import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .checks.tls import check_tls
from .models import URL, Scan
from .utils import normalize_url


@csrf_exempt
@require_http_methods(["GET", "POST"])
def scan_url(request):
    if request.method == "GET":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    raw_url = payload.get("url")
    try:
        normalized = normalize_url(raw_url)
    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=400)

    url_obj, _ = URL.objects.get_or_create(canonical_url=normalized)

    # TLS check + simple scoring
    tls = check_tls(normalized)

    score = 100
    risk = Scan.RISK_LOW
    confidence = Scan.CONF_MEDIUM

    checks = {"normalized": True, "tls": tls.__dict__}

    if not tls.ok:
        score -= 30
        risk = Scan.RISK_MEDIUM

    if tls.expired:
        score = min(score, 20)
        risk = Scan.RISK_HIGH

    if tls.days_to_expiry is not None and tls.days_to_expiry < 14 and not tls.expired:
        score -= 10
        risk = Scan.RISK_MEDIUM

    scan = Scan.objects.create(
        url=url_obj,
        score=max(0, min(100, score)),
        risk_level=risk,
        confidence=confidence,
        checks=checks,
    )

    return JsonResponse(
        {
            "scan_id": scan.id,
            "url": normalized,
            "score": scan.score,
            "risk_level": scan.risk_level,
            "confidence": scan.confidence,
            "checks": scan.checks,
            "message": "scan saved",
        }
    )
