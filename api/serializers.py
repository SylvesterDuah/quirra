# api/serializers.py
from rest_framework import serializers
from events.models import Event
from analysis.models import AnalysisResult
from flags.models import Flag


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Event
        fields = ["id", "project_id", "kind", "content", "metadata", "created_at"]
        read_only_fields = ["id", "created_at"]


class AnalysisResultSerializer(serializers.ModelSerializer):
    event_id = serializers.UUIDField(source="event.id", read_only=True)

    class Meta:
        model  = AnalysisResult
        fields = ["event_id", "scores", "neighbors", "labels", "created_at"]


class FlagSerializer(serializers.ModelSerializer):
    flag_id  = serializers.IntegerField(source="id", read_only=True)
    event_id = serializers.UUIDField(source="event.id", read_only=True)

    class Meta:
        model  = Flag
        fields = ["flag_id", "event_id", "severity", "reasons", "status", "created_at"]
