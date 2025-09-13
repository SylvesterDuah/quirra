# quirra/urls.py
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse

def health(_request):  # Render health check
    return JsonResponse({"ok": True, "service": "quirra"})

urlpatterns = [
    path("admin/", admin.site.urls),

    # Mount app under /api/
    path("api/", include("api.urls")),

    # Health for Render
    path("api/health", health),
]
