from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def scan_url(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        data = json.loads(request.body or "{}")
        url = data.get("url", "").strip()
        if not url:
            return JsonResponse({"error": "url is required"}, status=400)

        return JsonResponse({
            "url": url,
            "score": 0,
            "risk_level": "unknown",
            "message": "scan endpoint working"
        })
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid JSON"}, status=400)
