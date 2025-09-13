# analysis/models.py

from django.db import models

# Create your models here.
from events.models import Event

class AnalysisResult(models.Model):
    event = models.OneToOneField(Event, on_delete=models.CASCADE)
    scores = models.JSONField(default=dict) 
    neighbors = models.JSONField(default=list)
    labels = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
