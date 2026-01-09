import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .utils import normalize_url


@csrf_exempt
@require_http_methods(["GET", "POST"])
def scan_url(request):
    if request.method == "GET":
        return JsonResponse({"error": "POST required"}, status=405)

    # POST
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    raw_url = payload.get("url")
    try:
        normalized = normalize_url(raw_url)
    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=400)

    # For now keep your placeholder response, but return normalized URL
    return JsonResponse(
        {
            "url": normalized,
            "score": 0,
            "risk_level": "unknown",
            "message": "scan endpoint working",
        }
    )