# api/views.py (DRF style)
import os
import hashlib
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from events.models import Event
from analysis.models import AnalysisResult
from flags.models import Flag
from analysis.engine import compute_analysis

from .serializers import EventSerializer, AnalysisResultSerializer, FlagSerializer

import logging

logger = logging.getLogger(__name__)


def _derive_key_from_salt() -> bytes | None:
    """
    Return a bytes key that is suitable for blake2s key param (<= 32 bytes).
    If QUIRRA_USER_SALT is not set, return None.
    If salt is longer than 32 bytes, derive a 32-byte key by hashing the salt
    with SHA-256 and taking the first 32 bytes.
    """
    val = getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT", "")
    if not val:
        return None
    b = val.encode("utf-8")
    if len(b) <= 32:
        # OK to use raw bytes as key
        return b
    # Derive a 32-byte key deterministically
    digest = hashlib.sha256(b).digest()
    return digest[:32]

class HashUser(APIView):
    """
    POST /api/v1/hash   { "user_id": "stable-browser-or-account-id" }
    -> { "user_hash": "<hex blake2s keyed>" }
    This view is defensive: returns clear JSON errors and logs internal details.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = (request.data or {}).get("user_id", "")
            if not user_id:
                return Response({"detail": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)

            key = _derive_key_from_salt()
            if not key:
                # configuration problem; log note for operator
                logger.error("HashUser: QUIRRA_USER_SALT is not configured")
                return Response(
                    {"detail": "Server configuration error: QUIRRA_USER_SALT not set"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            # Use BLAKE2s keyed hashing to produce a stable user hash.
            # digest_size=32 -> 64 hex chars
            h = hashlib.blake2s(digest_size=32, key=key)
            h.update(user_id.encode("utf-8"))
            user_hash = h.hexdigest()
            return Response({"user_hash": user_hash})

        except Exception:
            # Log full stack trace for debugging but return generic 500 to clients.
            logger.exception("HashUser: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PostEvent(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ser = EventSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        event = ser.save()
        if event.kind == "response":
            compute_analysis(event)
        return Response({"event_id": str(event.pk)}, status=status.HTTP_201_CREATED)

class GetAnalysis(APIView):
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        event = get_object_or_404(Event, pk=event_id)
        try:
            ar = AnalysisResult.objects.get(event=event)
        except AnalysisResult.DoesNotExist:
            ar = compute_analysis(event)
        data = AnalysisResultSerializer(ar).data
        data["status"] = "done"
        return Response(data)

class FlagsList(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        flags = Flag.objects.order_by("-created_at")[:100]
        return Response(FlagSerializer(flags, many=True).data)
