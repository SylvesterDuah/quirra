# api/urls.py
from django.urls import path
from django.conf import settings
from django.http import JsonResponse

from . import views
from . import debug_views

urlpatterns = [
    path("v1/hash",                           views.HashUser.as_view(),    name="api_v1_hash"),
    path("v1/events",                         views.PostEvent.as_view(),   name="api_v1_events"),
    path("v1/events/<str:event_id>/analysis", views.GetAnalysis.as_view(), name="api_v1_event_analysis"),
    path("v1/flags",                          views.FlagsList.as_view(),   name="api_v1_flags"),
]

if getattr(settings, "QUIRRA_EXPOSE_DEBUG_ENDPOINT", False):
    urlpatterns += [
        path("v1/debug-status", debug_views.debug_status, name="api_v1_debug_status"),
    ]