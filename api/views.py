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
# DB MODE — always attempt real DB; fall back only if imports fail
# ------------------------------------------------------------------
USE_DB = True  

try:
    from events.models import Event
    from analysis.models import AnalysisResult
    from .serializers import EventSerializer, AnalysisResultSerializer
    from analysis.tasks import analyze_event  
except Exception as exc:
    logger.warning("api.views: DB imports failed, running in fallback mode: %s", exc)
    USE_DB = False


# ------------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------------
def _ephemeral_event_id(payload: dict) -> str:
    """Stable ephemeral event id for DB-less fallback mode."""
    try:
        j = json.dumps(payload or {}, sort_keys=True, ensure_ascii=False)
    except Exception:
        j = str(payload)
    return hashlib.sha256(j.encode("utf-8")).hexdigest()[:16]


def _derive_key_from_salt() -> Optional[bytes]:
    """Return a bytes key suitable for blake2s (<=32 bytes), or None."""
    val = getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT", "")
    if not val:
        return None
    b = val.encode("utf-8")
    if len(b) <= 32:
        return b
    return hashlib.sha256(b).digest()[:32]


def _check_ingest_secret(request) -> bool:
    """
    Validate INGEST_SECRET if configured.
    Accepts it as X-Ingest-Secret header or ?secret= query param.
    If INGEST_SECRET is empty, only allow requests from localhost.
    """
    secret = getattr(settings, "INGEST_SECRET", "") or os.environ.get("INGEST_SECRET", "")
    if secret:
        provided = (
            request.headers.get("X-Ingest-Secret")
            or request.GET.get("secret")
            or ""
        )
        return provided == secret
    remote = request.META.get("REMOTE_ADDR", "")
    return remote in ("127.0.0.1", "::1", "localhost")


# ------------------------------------------------------------------
# API Views
# ------------------------------------------------------------------
class HashUser(APIView):
    """
    POST /api/v1/hash
    Request:  { "user_id": "<stable-id>" }
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
            return Response({"user_hash": h.hexdigest()})
        except Exception:
            logger.exception("HashUser: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PostEvent(APIView):
    """
    POST /api/v1/events
    Ingests a prompt or response event and enqueues async analysis.
    Requires X-Ingest-Secret header (or localhost) when INGEST_SECRET is set.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            if not _check_ingest_secret(request):
                return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

            payload = request.data if isinstance(request.data, dict) else {}
            kind = payload.get("kind")
            content = payload.get("content")

            if not kind or not content:
                return Response(
                    {"detail": "kind and content fields are required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if kind not in ("prompt", "response"):
                return Response(
                    {"detail": "kind must be 'prompt' or 'response'"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not USE_DB:
                event_id = _ephemeral_event_id(payload)
                return Response(
                    {"event_id": event_id, "status": "created", "mode": "ephemeral"},
                    status=status.HTTP_201_CREATED,
                )

            event = Event.objects.create(
                kind=kind,
                content=content,
                content_sha256=Event.sha256(content),
                canonical_sha256=Event.sha256(" ".join(content.lower().split())),
                tokens_len=len(content.split()),
                metadata=payload.get("metadata") or {},
            )

            analyze_event.delay(str(event.pk))

            return Response(
                {"event_id": str(event.pk), "status": "created"},
                status=status.HTTP_201_CREATED,
            )

        except Exception:
            logger.exception("PostEvent: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAnalysis(APIView):
    """
    GET /api/v1/events/<event_id>/analysis
    Returns real analysis, or 202 if still processing.
    """
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        try:
            if not USE_DB:
                return Response(
                    {
                        "event_id": event_id,
                        "status": "unavailable",
                        "detail": "Running in DB-less mode; analysis not available.",
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            event = get_object_or_404(Event, pk=event_id)

            try:
                ar = AnalysisResult.objects.get(event=event)
            except AnalysisResult.DoesNotExist:
                return Response(
                    {"event_id": event_id, "status": "pending"},
                    status=status.HTTP_202_ACCEPTED,
                )

            return Response({
                "event_id": event_id,
                "status": "done",
                "scores": ar.scores,
                "neighbors": ar.neighbors,
            })

        except Exception:
            logger.exception("GetAnalysis: unexpected error for event_id=%s", event_id)
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FlagsList(APIView):
    """
    GET /api/v1/flags
    Returns flags, optionally filtered by ?severity= or ?status=
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            if not USE_DB:
                return Response([])

            from flags.models import Flag
            from .serializers import FlagSerializer

            qs = Flag.objects.select_related("event").order_by("-created_at")

            severity = request.GET.get("severity")
            if severity:
                qs = qs.filter(severity=severity)

            flag_status = request.GET.get("status")
            if flag_status:
                qs = qs.filter(status=flag_status)

            return Response(FlagSerializer(qs[:200], many=True).data)

        except Exception:
            logger.exception("FlagsList: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)