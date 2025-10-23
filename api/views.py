# api/views.py
import json
import hashlib
import logging
import os
from typing import Optional

from django.conf import settings
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

# --- Try to import DB-backed models/serializers/analysis engine.
USE_DB = True
try:
    from events.models import Event
    from analysis.models import AnalysisResult
    from .serializers import EventSerializer, AnalysisResultSerializer
    from analysis.engine import compute_analysis
except Exception as exc:  # pragma: no cover
    logger.info("api.views running in DB-less fallback mode: %s", exc)
    USE_DB = False


def _ephemeral_event_id(payload: dict) -> str:
    """
    Create a stable ephemeral event id for DB-less testing so clients can poll for analysis.
    """
    try:
        j = json.dumps(payload or {}, sort_keys=True, ensure_ascii=False)
    except Exception:
        j = str(payload)
    return hashlib.sha1(j.encode("utf-8")).hexdigest()[:16]


def _derive_key_from_salt() -> Optional[bytes]:
    """
    Return a bytes key suitable for blake2s key param (<= 32 bytes).
    If QUIRRA_USER_SALT is not set, return None.
    If salt is longer than 32 bytes, derive a 32-byte key by hashing the salt
    with SHA-256 and taking the first 32 bytes.
    """
    val = getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT", "")
    if not val:
        return None
    b = val.encode("utf-8")
    if len(b) <= 32:
        return b
    digest = hashlib.sha256(b).digest()
    return digest[:32]


# ------------------------------------------------------------------
# API Views
# ------------------------------------------------------------------
class HashUser(APIView):
    """
    POST /api/v1/hash
    Request payload: { "user_id": "<stable-id>" }
    Response: { "user_hash": "<hex 64 chars>" }
    Behavior:
      - If QUIRRA_USER_SALT is not configured -> 500 with JSON error
      - Otherwise compute BLAKE2s keyed digest (digest_size=32 -> 64 hex chars)
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = (request.data or {}).get("user_id", "")
            if not user_id:
                return Response({"detail": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)

            key = _derive_key_from_salt()
            if not key:
                logger.error("HashUser: QUIRRA_USER_SALT is not configured")
                return Response(
                    {"detail": "Server configuration error: QUIRRA_USER_SALT not set"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            h = hashlib.blake2s(digest_size=32, key=key)
            h.update(user_id.encode("utf-8"))
            user_hash = h.hexdigest()
            return Response({"user_hash": user_hash})
        except Exception:
            logger.exception("HashUser: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PostEvent(APIView):
    """
    POST /api/v1/events
    Accepts JSON payload with required fields:
      - kind: "prompt" or "response"
      - content: string
      - metadata: optional dict
    Returns: { "event_id": "<uuid or ephemeral id>" }
    Works in two modes:
      - USE_DB True: performs serializer validation and saves an Event instance.
      - USE_DB False: returns an ephemeral id for testing and does not persist.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            payload = request.data if isinstance(request.data, dict) else {}
            kind = payload.get("kind")
            content = payload.get("content")
            if not kind or not content:
                return Response({"detail": "kind and content fields are required"}, status=status.HTTP_400_BAD_REQUEST)

            if USE_DB:
                ser = EventSerializer(data=payload)
                ser.is_valid(raise_exception=True)
                event = ser.save()
                # Optionally compute analysis synchronously for responses.
                if getattr(event, "kind", "") == "response":
                    try:
                        compute_analysis(event)
                    except Exception:
                        logger.exception("compute_analysis failed for event %s (continuing)", getattr(event, "pk", "<unknown>"))
                return Response({"event_id": str(event.pk)}, status=status.HTTP_201_CREATED)
            else:
                event_id = _ephemeral_event_id(payload)
                return Response({"event_id": event_id}, status=status.HTTP_201_CREATED)

        except Exception:
            logger.exception("PostEvent: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAnalysis(APIView):
    """
    GET /api/v1/events/<event_id>/analysis
    If DB available: return AnalysisResult (or compute on demand)
    If DB not available: return canned example analysis to allow front-end testing.
    """
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        try:
            if USE_DB:
                event = get_object_or_404(Event, pk=event_id)
                try:
                    ar = AnalysisResult.objects.get(event=event)
                except AnalysisResult.DoesNotExist:
                    ar = compute_analysis(event)
                data = AnalysisResultSerializer(ar).data
                data["status"] = "done"
                return Response(data)
            else:
                sample = {
                    "event_id": event_id,
                    "status": "done",
                    "scores": {
                        "risk": 12,
                        "duplication_pct": 4,
                        "style_pct": 18,
                        "seen_count": 0,
                    },
                    "neighbors": [],
                }
                return Response(sample)
        except Exception:
            logger.exception("GetAnalysis: unexpected error for event_id=%s", event_id)
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FlagsList(APIView):
    """
    GET /api/v1/flags -> latest flags (100)
    Returns empty list in DB-less mode.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            if USE_DB:
                from flags.models import Flag  # local import to avoid top-level failure when DB missing
                from .serializers import FlagSerializer
                flags = Flag.objects.order_by("-created_at")[:100]
                return Response(FlagSerializer(flags, many=True).data)
            else:
                return Response([])
        except Exception:
            logger.exception("FlagsList: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
