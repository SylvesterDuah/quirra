# analysis/engine.py
#
# Fully self-contained — does not rely on algorithm.py being importable.
# Uses inline implementations for everything so there are zero import-time
# failures regardless of which optional packages are installed.

import re
import logging
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from events.models import Event

logger = logging.getLogger(__name__)


# ── Inline implementations (no external dependencies) ────────────────────────
# These are used directly. We do NOT import from algorithm.py to avoid silent
# crashes when blake3/datasketch are missing.

def _tokens(text: str) -> list:
    return re.findall(r"[a-z0-9']+", (text or "").lower())


def _shingles(words: list, k: int = 3) -> set:
    if len(words) < k:
        return set()
    return set(zip(*[words[i:] for i in range(k)]))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def _style_score(text: str) -> float:
    """Returns 0-1 where 1 = maximally repetitive."""
    words = _tokens(text)
    if not words:
        return 0.0
    ttr = len(set(words)) / len(words)
    return round(max(0.0, 1.0 - ttr), 4)


_POLICY_WORDS = [
    "bypass", "jailbreak", "exploit",
    "ignore previous instructions", "ignore all instructions",
    "phishing", "malware", "weapon", "bomb", "poison",
    "harm", "kill", "deepfake", "hack", "dox", "password",
    "racist", "sexist", "hate speech",
]
_LM_TELLS = ["as an ai", "as a language model", "cannot assist with that"]


def _risk_score(text: str, dup_pct: float) -> int:
    """Returns integer 0-100."""
    t    = (text or "").lower()
    hits = sum(1 for w in _POLICY_WORDS if w in t)
    jb   = 1 if any(p in t for p in ["jailbreak", "bypass", "ignore previous", "ignore all"]) else 0
    lm   = 1 if any(p in t for p in _LM_TELLS) else 0
    base = (dup_pct / 100.0) * 30 + hits * 12 + jb * 30 + lm * 10
    return int(min(100, max(0, round(base))))


# ── Constants ─────────────────────────────────────────────────────────────────

MATCH_THRESHOLD = 0.60   # Jaccard sim to count as "seen before"
SCAN_LIMIT      = 500    # Max events to compare against
MAX_NEIGHBORS   = 10     # Max neighbors to store


# ── Main entry point ──────────────────────────────────────────────────────────

def compute_analysis(event: "Event") -> None:
    """
    Compute + persist analysis. Safe to call synchronously.
    Catches all exceptions so PostEvent always gets a 201.
    """
    try:
        from analysis.models import AnalysisResult
        from events.models import Event as EventModel

        content = event.content or ""
        toks    = _tokens(content)
        sh_a    = _shingles(toks, 3)

        # ── Neighbour search ──────────────────────────────────────────────────
        project_id = getattr(event, "project_id", None)

        qs = EventModel.objects.filter(kind=event.kind).exclude(pk=event.pk)
        if project_id:
            qs = qs.filter(project_id=project_id)

        neighbors   = []
        max_jaccard = 0.0
        seen_count  = 0

        for other in qs.order_by("-created_at")[:SCAN_LIMIT]:
            sh_b = _shingles(_tokens(other.content or ""), 3)
            sim  = _jaccard(sh_a, sh_b)

            if sim >= MATCH_THRESHOLD:
                seen_count += 1
                if sim > max_jaccard:
                    max_jaccard = sim
                meta = other.metadata or {}
                neighbors.append({
                    "event_id":   str(other.pk),
                    "when":       other.created_at.isoformat() if other.created_at else None,
                    "context":    meta.get("context"),
                    "url":        meta.get("url"),
                    "similarity": round(sim, 4),
                })

        neighbors.sort(key=lambda n: n["similarity"], reverse=True)
        neighbors = neighbors[:MAX_NEIGHBORS]

        # ── Scores ────────────────────────────────────────────────────────────
        dup_pct   = round(max_jaccard * 100, 1)
        style_pct = round(_style_score(content) * 100, 1)
        risk      = _risk_score(content, dup_pct)

        scores = {
            "duplication_pct": dup_pct,
            "style_pct":       style_pct,
            "risk":            risk,
            "seen_count":      seen_count,
            "kind":            event.kind,
        }

        # ── Labels ────────────────────────────────────────────────────────────
        labels: list = []
        if max_jaccard >= 0.90:
            labels.append("duplicate:near")
        elif max_jaccard >= 0.70:
            labels.append("duplicate:similar")
        elif max_jaccard >= MATCH_THRESHOLD:
            labels.append("duplicate:partial")
        if style_pct >= 70:
            labels.append("style:repetitive")
        if risk >= 70:
            labels.append("risk:high")
        elif risk >= 40:
            labels.append("risk:medium")

        # ── Persist ───────────────────────────────────────────────────────────
        AnalysisResult.objects.update_or_create(
            event=event,
            defaults={
                "scores":    scores,
                "neighbors": neighbors,
                "labels":    labels,
            },
        )

        logger.info(
            "engine: event=%s kind=%s dup=%.1f%% risk=%d seen=%d labels=%s",
            event.pk, event.kind, dup_pct, risk, seen_count, labels,
        )

        # ── Auto-flag ─────────────────────────────────────────────────────────
        _maybe_flag(event, labels, risk, dup_pct)

    except Exception:
        logger.exception(
            "engine: compute_analysis failed for event=%s",
            getattr(event, "pk", "?"),
        )


def _maybe_flag(event: "Event", labels: list, risk: int, dup_pct: float) -> None:
    try:
        from flags.models import Flag

        reasons:  list = []
        severity: str  = "low"

        if "duplicate:near" in labels or dup_pct >= 90:
            reasons.append("near-duplicate")
            severity = "med"
        elif "duplicate:similar" in labels or "duplicate:partial" in labels:
            reasons.append("partial-duplicate")

        if risk >= 70:
            reasons.append("high-risk")
            severity = "high"
        elif risk >= 40:
            reasons.append("medium-risk")
            if severity == "low":
                severity = "med"

        if "style:repetitive" in labels:
            reasons.append("style-repetitive")

        if reasons:
            Flag.objects.get_or_create(
                event=event,
                defaults={"severity": severity, "reasons": reasons},
            )

    except Exception:
        logger.exception(
            "engine: _maybe_flag failed for event=%s",
            getattr(event, "pk", "?"),
        )