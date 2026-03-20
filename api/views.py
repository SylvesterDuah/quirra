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

USE_DB = True
try:
    from events.models import Event
    from analysis.models import AnalysisResult
    from analysis.tasks import analyze_event
except Exception as exc:
    logger.warning("api.views: DB imports failed: %s", exc)
    USE_DB = False

HAS_CELERY = False
try:
    from celery import current_app as _celery_app
    _celery_app.connection().ensure_connection(max_retries=1, timeout=2)
    HAS_CELERY = True
except Exception:
    logger.warning("api.views: Celery unavailable — running synchronously")


def _run_analysis(event_id: str) -> None:
    if HAS_CELERY:
        analyze_event.delay(event_id)
    else:
        try:
            from analysis.engine import compute_analysis
            ev = Event.objects.get(pk=event_id)
            compute_analysis(ev)
        except Exception as exc:
            logger.error("inline analysis failed for %s: %s", event_id, exc)


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


# ── Views ─────────────────────────────────────────────────────────────────────

class HashUser(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            user_id = (request.data or {}).get("user_id", "")
            if not user_id:
                return Response({"detail": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)
            key = _derive_key_from_salt()
            if not key:
                return Response({"user_hash": hashlib.sha256(user_id.encode()).hexdigest()})
            h = hashlib.blake2s(digest_size=32, key=key)
            h.update(user_id.encode("utf-8"))
            return Response({"user_hash": h.hexdigest()})
        except Exception:
            logger.exception("HashUser error")
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
                return Response({"detail": "kind and content required"}, status=status.HTTP_400_BAD_REQUEST)
            if kind not in ("prompt", "response"):
                return Response({"detail": "kind must be prompt or response"}, status=status.HTTP_400_BAD_REQUEST)

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

            return Response({"event_id": str(event.pk), "status": "created"}, status=status.HTTP_201_CREATED)

        except Exception:
            logger.exception("PostEvent error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAnalysis(APIView):
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        try:
            if not USE_DB:
                return Response({"event_id": event_id, "status": "unavailable"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

            event = get_object_or_404(Event, pk=event_id)

            try:
                ar = AnalysisResult.objects.get(event=event)
            except AnalysisResult.DoesNotExist:
                return Response({"event_id": event_id, "status": "pending"}, status=status.HTTP_202_ACCEPTED)

            # ── Build duplicate alert ─────────────────────────────────────────
            # FIX: threshold lowered from 90% to 60% to match engine.py's
            # MATCH_THRESHOLD. Was 90% which meant most duplicates were never
            # flagged. Also now checks neighbors list directly for highest sim.
            duplicate_alert = None
            if ar.scores:
                dup_pct    = ar.scores.get("duplication_pct", 0)
                seen_count = ar.scores.get("seen_count", 0)

                # Find actual highest similarity from neighbors
                top_sim = dup_pct
                if ar.neighbors:
                    sims = [n.get("similarity", 0) * 100 for n in ar.neighbors if n.get("similarity")]
                    if sims:
                        top_sim = max(top_sim, max(sims))

                # FIX: flag at 60%+ similarity (was 90%)
                if top_sim >= 60 and seen_count > 0:
                    first_seen  = None
                    source_url  = None
                    neighbor_ids = [n.get("event_id") for n in ar.neighbors if n.get("event_id")]
                    if neighbor_ids:
                        try:
                            matches = Event.objects.filter(pk__in=neighbor_ids).order_by("created_at")
                            if matches.exists():
                                earliest   = matches.first()
                                first_seen = earliest.created_at.isoformat()
                                source_url = (earliest.metadata or {}).get("url")
                        except Exception:
                            pass

                    duplicate_alert = {
                        "detected":   True,
                        "similarity": round(top_sim, 1),
                        "seen_count": seen_count,
                        "first_seen": first_seen,
                        "source_url": source_url,
                        "message":    _dup_message(round(top_sim, 1), seen_count),
                    }

            return Response({
                "event_id":        event_id,
                "status":          "done",
                "scores":          ar.scores,
                "neighbors":       ar.neighbors,
                "labels":          ar.labels if hasattr(ar, "labels") else [],
                "duplicate_alert": duplicate_alert,
            })

        except Exception:
            logger.exception("GetAnalysis error for %s", event_id)
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _dup_message(sim: float, seen_count: int) -> str:
    times = f"{seen_count} time{'s' if seen_count != 1 else ''}"
    if sim >= 99: return f"This response is identical to one seen {times} before."
    if sim >= 90: return f"This response is nearly identical to one seen {times} before."
    if sim >= 75: return f"This response is very similar to one seen {times} before."
    return f"This response is {sim:.0f}% similar to one seen {times} before."


class GetDuplicates(APIView):
    permission_classes = [AllowAny]

    def get(self, request, event_id: str):
        try:
            if not USE_DB:
                return Response({"event_id": event_id, "duplicates": [], "total": 0})

            event = get_object_or_404(Event, pk=event_id)
            try:
                ar = AnalysisResult.objects.get(event=event)
            except AnalysisResult.DoesNotExist:
                return Response({"detail": "Analysis not ready"}, status=status.HTTP_202_ACCEPTED)

            enriched = []
            for n in ar.neighbors:
                nid = n.get("event_id")
                if not nid:
                    continue
                try:
                    other = Event.objects.get(pk=nid)
                    enriched.append({
                        "event_id":   str(other.pk),
                        "similarity": n.get("similarity", 0),
                        "seen_at":    other.created_at.isoformat(),
                        "source_url": (other.metadata or {}).get("url"),
                        "context":    (other.metadata or {}).get("context"),
                        "excerpt":    (other.content or "")[:200],
                    })
                except Event.DoesNotExist:
                    continue

            enriched.sort(key=lambda x: x["similarity"], reverse=True)
            return Response({"event_id": event_id, "duplicates": enriched, "total": len(enriched)})

        except Exception:
            logger.exception("GetDuplicates error for %s", event_id)
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
            if request.GET.get("severity"):
                qs = qs.filter(severity=request.GET["severity"])
            if request.GET.get("status"):
                qs = qs.filter(status=request.GET["status"])
            return Response(FlagSerializer(qs[:200], many=True).data)
        except Exception:
            logger.exception("FlagsList error")
            return Response({"detail": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)