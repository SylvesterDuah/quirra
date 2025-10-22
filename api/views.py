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

def _salt() -> bytes:
    val = getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT", "")
    return val.encode("utf-8")

class HashUser(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = (request.data or {}).get("user_id", "")
        if not user_id:
            return Response({"detail": "user_id required"}, status=400)
        key = _salt()
        if not key:
            return Response({"detail": "QUIRRA_USER_SALT not configured"}, status=500)
        h = hashlib.blake2s(digest_size=32, key=key)
        h.update(user_id.encode("utf-8"))
        return Response({"user_hash": h.hexdigest()})

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
