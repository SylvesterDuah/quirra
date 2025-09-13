# flags/models.py

from django.db import models

# Create your models here.
from events.models import Event

class Flag(models.Model):
    SEV = [("low","low"),("med","med"),("high","high")]
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    severity = models.CharField(max_length=5, choices=SEV)
    reasons = models.JSONField(default=list)
    status = models.CharField(max_length=10, default="open")
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

class Review(models.Model):
    flag = models.ForeignKey(Flag, on_delete=models.CASCADE)
    action = models.CharField(max_length=20) 
    notes = models.TextField(blank=True)
    suggestions = models.JSONField(default=list)
    reviewer = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
