# events/models.py
from django.db import models
import uuid, hashlib


class Event(models.Model):
    KIND_CHOICES = [("prompt", "prompt"), ("response", "response")]

    id               = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    kind             = models.CharField(max_length=10, choices=KIND_CHOICES)
    content          = models.TextField(null=True, blank=True)
    content_sha256   = models.CharField(max_length=64, db_index=True, default="")
    canonical_sha256 = models.CharField(max_length=64, db_index=True, default="")
    tokens_len       = models.IntegerField(default=0)
    metadata         = models.JSONField(default=dict)
    created_at       = models.DateTimeField(auto_now_add=True)
    project_id       = models.CharField(max_length=128, db_index=True, null=True, blank=True)
    simhash          = models.BigIntegerField(null=True, blank=True, db_index=True)

    @staticmethod
    def sha256(s: str) -> str:
        return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

    def __str__(self):
        return f"{self.kind}:{self.id}"