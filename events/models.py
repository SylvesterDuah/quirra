# events/models.py

from django.db import models
import uuid, hashlib

class Event(models.Model):
    KIND_CHOICES = [("prompt","prompt"),("response","response")]
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES)
    content = models.TextField(null=True, blank=True)
    content_sha256 = models.CharField(max_length=64, db_index=True, default="")
    canonical_sha256 = models.CharField(max_length=64, db_index=True, default="")
    tokens_len = models.IntegerField(default=0)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def sha256(s: str) -> str:
        return hashlib.sha256((s or "").encode("utf-8")).hexdigest()
