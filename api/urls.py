# api/urls.py
from django.urls import path
from .views import PostEvent, GetAnalysis, FlagsList, HashUser

urlpatterns = [
    path("v1/events", PostEvent.as_view()),
    path("v1/events/<uuid:event_id>/analysis", GetAnalysis.as_view()),
    path("v1/flags", FlagsList.as_view()),
    path("v1/hash", HashUser.as_view()),
]
