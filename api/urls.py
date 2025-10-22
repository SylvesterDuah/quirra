# api/urls.py
from django.urls import path
from django.conf import settings
from django.http import JsonResponse

from . import debug_views 

# choose module: DB-less test_views in DEBUG, real DRF views otherwise
if getattr(settings, "DEBUG", False):
    from . import test_views as views
else:
    from . import views

# helper fallback if FlagsList doesn't exist
def flags_empty(request):
    # return empty array of flags (safe default for testing)
    return JsonResponse([], safe=False)

# pick callable views (use .as_view() for class-based views)
hash_view = None
events_view = None
analysis_view = None
flags_view = None

# hash
if hasattr(views, "HashUser"):
    # DRF class-based
    hash_view = views.HashUser.as_view()
elif hasattr(views, "test_hash"):
    hash_view = views.test_hash
else:
    # fallback: simple 501
    def _not_impl_hash(request):
        return JsonResponse({"detail": "hash endpoint not implemented"}, status=501)
    hash_view = _not_impl_hash

# events (POST)
if hasattr(views, "PostEvent"):
    events_view = views.PostEvent.as_view()
elif hasattr(views, "test_event_create"):
    events_view = views.test_event_create
else:
    def _not_impl_events(request):
        return JsonResponse({"detail": "events endpoint not implemented"}, status=501)
    events_view = _not_impl_events

# analysis (GET)
if hasattr(views, "GetAnalysis"):
    analysis_view = views.GetAnalysis.as_view()
elif hasattr(views, "test_event_analysis"):
    analysis_view = views.test_event_analysis
else:
    def _not_impl_analysis(request, event_id=None):
        return JsonResponse({"detail": "analysis endpoint not implemented"}, status=501)
    analysis_view = _not_impl_analysis

# flags
if hasattr(views, "FlagsList"):
    flags_view = views.FlagsList.as_view()
else:
    flags_view = flags_empty

urlpatterns = [
    path("v1/hash", hash_view, name="api_v1_hash"),
    path("v1/events", events_view, name="api_v1_events"),
    path("v1/events/<str:event_id>/analysis", analysis_view, name="api_v1_event_analysis"),
    path("v1/flags", flags_view, name="api_v1_flags"),
    path("v1/debug-status", debug_views.debug_status, name="api_v1_debug_status"),

]
