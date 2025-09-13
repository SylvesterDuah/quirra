# quirra/urls.py
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse, JsonResponse

def root_ok(_request):
    # Used by Render's health check when healthCheckPath: "/"
    return HttpResponse("ok", content_type="text/plain", status=200)

def health(_request):
    # Optional JSON health endpoint (manual checks, uptime monitors, etc.)
    return JsonResponse({"ok": True, "service": "quirra"})

urlpatterns = [
    # Health for Render at root
    path("", root_ok),

    # Admin
    path("admin/", admin.site.urls),

    # API
    path("api/", include("api.urls")),

    # Health endpoints (both with and without / for robustness)
    path("api/health/", health),
    path("api/health", health),   # optional: allow no trailing slash too
    path("health/", health),      # optional: root health path if you ever switch back
]
