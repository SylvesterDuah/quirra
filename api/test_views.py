# api/test_views.py
import json
import hashlib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

@require_http_methods(["POST", "GET"])
@csrf_exempt
def test_hash(request):
    """
    Lightweight test-only endpoint that returns a deterministic hash of user_id
    without relying on QUIRRA_USER_SALT or the database.
    Use only for testing/debugging.
    """
    try:
        if request.method == "POST":
            try:
                body = json.loads(request.body.decode("utf-8") or "{}")
            except Exception:
                return JsonResponse({"detail": "invalid json"}, status=400)
            user_id = body.get("user_id") or "anon"
        else:
            user_id = request.GET.get("user_id", "anon")
    except Exception:
        user_id = "anon"

    h = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:40]
    return JsonResponse({"user_hash": h})
