import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

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

    scan = Scan.objects.create(
        url=url_obj,
        score=0,
        risk_level=Scan.RISK_UNKNOWN,
        confidence=Scan.CONF_LOW,
        checks={"normalized": True},
    )

    return JsonResponse(
        {
            "scan_id": scan.id,
            "url": normalized,
            "score": scan.score,
            "risk_level": scan.risk_level,
            "confidence": scan.confidence,
            "message": "scan saved",
        }
    )