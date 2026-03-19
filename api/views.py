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
# DB imports
# ------------------------------------------------------------------
USE_DB = True

try:
    from events.models import Event
    from analysis.models import AnalysisResult
    from analysis.tasks import analyze_event
except Exception as exc:
    logger.warning("api.views: DB imports failed, running in fallback mode: %s", exc)
    USE_DB = False

# ------------------------------------------------------------------
# Celery availability — detect at startup, fall back to sync
# ------------------------------------------------------------------
HAS_CELERY = False
try:
    from celery import current_app as _celery_app
    _celery_app.connection().ensure_connection(max_retries=1, timeout=2)
    HAS_CELERY = True
except Exception:
    logger.warning("api.views: Celery/Redis unavailable — analysis will run synchronously")


def _run_analysis(event_id: str) -> None:
    """Dispatch to Celery if available, otherwise run inline."""
    if HAS_CELERY:
        analyze_event.delay(event_id)
    else:
        try:
            from analysis.engine import compute_analysis
            ev = Event.objects.get(pk=event_id)
            compute_analysis(ev)
        except Exception as exc:
            logger.error("api.views: inline analysis failed for %s: %s", event_id, exc)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _ephemeral_event_id(payload: dict) -> str:
    try:
        j = json.dumps(payload or {}, sort_keys=True, ensure_ascii=False)
    except Exception:
        j = str(payload)
    return hashlib.sha256(j.encode("utf-8")).hexdigest()[:16]


def _derive_key_from_salt() -> Optional[bytes]:
    val = getattr(settings, "QUIRRA_USER_SALT", "") or os.environ.get("QUIRRA_USER_SALT", "")
    if not val:
        return None
    b = val.encode("utf-8")
    return b if len(b) <= 32 else hashlib.sha256(b).digest()[:32]


def _check_ingest_secret(request) -> bool:
    """
    FIX: Previous version fell through to a REMOTE_ADDR whitelist when
    INGEST_SECRET was blank. On Render the REMOTE_ADDR is the load balancer
    IP — never 127.0.0.1 — so every single request returned 403 Forbidden.

    New rules:
      - INGEST_SECRET set   → require matching X-Ingest-Secret or X-Quirra-Secret header
      - INGEST_SECRET blank → allow all (open/public mode)
    """
    secret = getattr(settings, "INGEST_SECRET", "") or os.environ.get("INGEST_SECRET", "")
    if not secret:
        return True  
    provided = (
        request.headers.get("X-Ingest-Secret")
        or request.headers.get("X-Quirra-Secret")  
        or request.GET.get("secret")
        or ""
    )
    return provided == secret


# ------------------------------------------------------------------
# Views
# ------------------------------------------------------------------

class HashUser(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = (request.data or {}).get("user_id", "")
            if not user_id:
                return Response({"detail": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)

            key = _derive_key_from_salt()
            if not key:
                logger.warning("HashUser: QUIRRA_USER_SALT not set, using plain SHA-256 fallback")
                return Response({"user_hash": hashlib.sha256(user_id.encode()).hexdigest()})

            h = hashlib.blake2s(digest_size=32, key=key)
            h.update(user_id.encode("utf-8"))
            return Response({"user_hash": h.hexdigest()})
        except Exception:
            logger.exception("HashUser: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PostEvent(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            if not _check_ingest_secret(request):
                return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

            payload = request.data if isinstance(request.data, dict) else {}
            kind    = payload.get("kind")
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
                return Response(
                    {"event_id": _ephemeral_event_id(payload), "status": "created", "mode": "ephemeral"},
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

            _run_analysis(str(event.pk))

            return Response(
                {"event_id": str(event.pk), "status": "created"},
                status=status.HTTP_201_CREATED,
            )

        except Exception:
            logger.exception("PostEvent: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAnalysis(APIView):
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        try:
            if not USE_DB:
                return Response(
                    {"event_id": event_id, "status": "unavailable",
                     "detail": "Running in DB-less mode."},
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
                "event_id":  event_id,
                "status":    "done",
                "scores":    ar.scores,
                "neighbors": ar.neighbors,
                # FIX: labels were written by engine but never returned here
                "labels":    ar.labels if hasattr(ar, "labels") else [],
            })

        except Exception:
            logger.exception("GetAnalysis: unexpected error for event_id=%s", event_id)
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FlagsList(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            if not USE_DB:
                return Response([])

            from flags.models import Flag
            from .serializers import FlagSerializer

            qs = Flag.objects.select_related("event").order_by("-created_at")
            severity    = request.GET.get("severity")
            flag_status = request.GET.get("status")
            if severity:
                qs = qs.filter(severity=severity)
            if flag_status:
                qs = qs.filter(status=flag_status)

            return Response(FlagSerializer(qs[:200], many=True).data)

        except Exception:
            logger.exception("FlagsList: unexpected error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)