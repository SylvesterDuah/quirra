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

# ------------------------------------------------------------------
# FORCE DB-LESS MODE FOR TESTING
# ------------------------------------------------------------------
USE_DB = False  # Always run in fallback mode for testing (no database)

# You can safely comment this import block out while testing.
try:
    from events.models import Event
    from analysis.models import AnalysisResult
    from .serializers import EventSerializer, AnalysisResultSerializer
    from analysis.engine import compute_analysis
except Exception as exc:  # pragma: no cover
    logger.info("api.views running in DB-less fallback mode: %s", exc)
    USE_DB = False


# ------------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------------
def _ephemeral_event_id(payload: dict) -> str:
    """Create a stable ephemeral event id for DB-less testing so clients can poll for analysis."""
    try:
        j = json.dumps(payload or {}, sort_keys=True, ensure_ascii=False)
    except Exception:
        j = str(payload)
    return hashlib.sha1(j.encode("utf-8")).hexdigest()[:16]


def _derive_key_from_salt() -> Optional[bytes]:
    """
    Return a bytes key suitable for blake2s key param (<= 32 bytes).
    If QUIRRA_USER_SALT is not set, return None.
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
    Works in two modes:
      - DB-less: returns ephemeral id
      - DB: saves and analyzes (disabled in this mode)
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            payload = request.data if isinstance(request.data, dict) else {}
            kind = payload.get("kind")
            content = payload.get("content")
            if not kind or not content:
                return Response(
                    {"detail": "kind and content fields are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Always fallback path (no DB writes)
            event_id = _ephemeral_event_id(payload)
            return Response({"event_id": event_id, "status": "created"}, status=status.HTTP_201_CREATED)

        except Exception:
            logger.exception("PostEvent: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAnalysis(APIView):
    """
    GET /api/v1/events/<event_id>/analysis
    Always returns a canned example analysis in DB-less mode.
    """
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        try:
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
    GET /api/v1/flags
    Always returns empty list in DB-less mode.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            return Response([])
        except Exception:
            logger.exception("FlagsList: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
