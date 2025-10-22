# api/test_views.py
import json
import hashlib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def simple_hash_user(user_id: str) -> str:
    h = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:40]
    return h

@csrf_exempt
def test_hash(request):
    try:
        payload = json.loads(request.body.decode() or "{}")
        user_id = payload.get("user_id") or "anon"
    except Exception:
        return JsonResponse({"detail": "invalid json"}, status=400)
    user_hash = simple_hash_user(user_id)
    return JsonResponse({"user_hash": user_hash})

@csrf_exempt
def test_event_create(request):
    try:
        payload = json.loads(request.body.decode() or "{}")
    except Exception:
        return JsonResponse({"detail": "invalid json"}, status=400)
    event_id = hashlib.sha1(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    return JsonResponse({"event_id": event_id})

def test_event_analysis(request, event_id):
    sample = {
        "event_id": event_id,
        "status": "done",
        "scores": {
            "risk": 12,
            "duplication_pct": 4,
            "style_pct": 18,
            "seen_count": 0
        },
        "neighbors": []
    }
    return JsonResponse(sample)
