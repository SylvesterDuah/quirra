# analysis/tasks.py
from celery import shared_task
from events.models import Event
from .engine import compute_analysis

@shared_task
def analyze_event(event_id: str):
    ev = Event.objects.get(pk=event_id)
    compute_analysis(ev)
    return str(event_id)
