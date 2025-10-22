# api/debug_views.py
import hashlib
import os
import json
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db import connections, DEFAULT_DB_ALIAS
from django.db.utils import OperationalError

@require_http_methods(["GET", "POST"])
@csrf_exempt
def debug_status(request):
    """
    Returns helpful diagnostics (no secrets).
    - salt_present: bool
    - db_connects: bool (attempts a lightweight DB cursor call)
    - example_hash: deterministic truncated sha256 of provided user_id (no key exposure)
    Use POST with {"user_id":"..."} to get example_hash.
    """
    salt_present = bool(getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT"))
    # test DB connectivity
    db_ok = False
    try:
        conn = connections[DEFAULT_DB_ALIAS]
        # try to open a cursor, but do not run queries that change data
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            _ = cur.fetchone()
        db_ok = True
    except OperationalError:
        db_ok = False
    except Exception:
        # other errors - still mark as not ok but don't include stack in response
        db_ok = False

    # sample deterministic test hash (sha256 hex truncated) — safe, not the keyed user hash used by prod.
    example_hash = None
    try:
        body = {}
        if request.body:
            try:
                body = json.loads(request.body.decode("utf-8") or "{}")
            except Exception:
                body = {}
        user_id = body.get("user_id") or request.GET.get("user_id") or "anon"
        example_hash = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:40]
    except Exception:
        example_hash = None

    return JsonResponse({
        "salt_present": salt_present,
        "db_ok": db_ok,
        "example_hash": example_hash,
        "note": "This endpoint is for debugging only; it does not reveal secrets."
    })
