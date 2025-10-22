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

def _salt() -> bytes:
    # Return bytes for keyed hashing. Prioritize settings then environment.
    val = getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT", "")
    return (val or "").encode("utf-8")

class HashUser(APIView):
    """
    POST /api/v1/hash { "user_id": "..." } -> { "user_hash": "<hex>" }
    Handles errors gracefully and logs details to server logs.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = (request.data or {}).get("user_id", "")
            if not user_id:
                return Response({"detail": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)

            key = _salt()
            if not key:
                # defensive: log once and return 500 with non-secret message
                logger.error("HashUser: QUIRRA_USER_SALT not configured")
                return Response({"detail": "Server configuration error (salt missing)"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Use BLAKE2s keyed hashing for stable mapping without storing raw ids
            h = hashlib.blake2s(digest_size=32, key=key)
            h.update(user_id.encode("utf-8"))
            return Response({"user_hash": h.hexdigest()})
        except Exception as exc:
            # Log the full exception (stack trace) to server logs (not returned to user)
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
