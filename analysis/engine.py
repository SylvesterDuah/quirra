# analysis/engine.py
from __future__ import annotations
from typing import List, Any
import re

from events.models import Event
from flags.models import Flag
from analysis.models import AnalysisResult

WORD_RE = re.compile(r"[A-Za-z0-9']+")

def _tokens(text: str) -> List[str]:
    return WORD_RE.findall((text or "").lower())

def _shingles(tokens: List[str], k: int = 3) -> set[tuple[str, ...]]:
    if len(tokens) < k:
        return set()
    return {tuple(tokens[i:i+k]) for i in range(len(tokens)-k+1)}

def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b) or 1
    return inter / union

def _style_repetition(tokens: List[str]) -> float:
    # crude sameness proxy: 1 - type/token ratio
    if not tokens:
        return 0.0
    types = len(set(tokens))
    ttr = types / len(tokens)
    return max(0.0, min(1.0, 1.0 - ttr))

RISK_WORDS = [
    "jailbreak","bypass","exploit","leak","nsfw","deepfake","cheat",
    "malware","crack","pirated","weapon","bomb","poison",
]

def _risk_score(prompt_text: str, response_text: str | None, duplication: float) -> int:
    score = 0
    p = (prompt_text or "").lower()
    r = (response_text or "").lower() if response_text else ""
    hay = f"{p} {r}"
    if any(w in hay for w in RISK_WORDS):
        score += 35
    if "as an ai" in r or "language model" in r:
        score += 10
    score += int(duplication * 60)  # high duplication => higher risk
    return max(0, min(100, score))

def compute_analysis(event: Event) -> AnalysisResult:
    """
    Synchronously compute an analysis for an Event:
    - kind == "prompt": style + risk only (no duplication)
    - kind == "response": near-duplicate Jaccard, style, risk, neighbors with when/context/url
    """
    text = (event.content or "").strip()
    toks = _tokens(text)
    is_prompt = (event.kind == "prompt")

    if is_prompt:
        duplication = 0.0
        style_same  = _style_repetition(toks)
        risk        = _risk_score(text, None, duplication)
        seen_count  = 0
        neighbors: list[dict[str, Any]] = []
    else:
        sh_a = _shingles(toks, 3)
        qs = Event.objects.filter(kind="response").exclude(pk=event.pk)
        if getattr(event, "project_id", None):
            qs = qs.filter(project_id=event.project_id)

        neighbors = []
        top_sim = 0.0
        seen_count = 0

        for other in qs.order_by("-created_at")[:1000]:
            sh_b = _shingles(_tokens(other.content or ""), 3)
            sim = _jaccard(sh_a, sh_b)
            top_sim = max(top_sim, sim)
            if sim >= 0.80:
                seen_count += 1
                neighbors.append({
                    "event_id": str(other.pk),
                    "when": other.created_at.isoformat(),
                    "context": (other.metadata or {}).get("context"),
                    "url": (other.metadata or {}).get("url"),
                    "similarity": round(sim, 3),
                })
            if len(neighbors) >= 10:
                break

        duplication = max(0.0, min(1.0, top_sim))
        style_same  = _style_repetition(toks)
        risk        = _risk_score("", text, duplication)

    scores = {
        "duplication_pct": int(round(duplication * 100)),
        "style_pct":       int(round(style_same  * 100)),
        "risk":            int(risk),
        "seen_count":      int(seen_count),
        "kind":            event.kind,
    }

    ar, _ = AnalysisResult.objects.update_or_create(
        event=event,
        defaults={"scores": scores, "neighbors": neighbors},
    )

    # Optional flags (responses emphasized)
    if not is_prompt:
        reasons = []
        if scores["duplication_pct"] >= 90: reasons.append("duplication-high")
        if scores["seen_count"] >= 3:       reasons.append("seen-many")
        if scores["risk"] >= 70:            reasons.append("policy-risk")
        if reasons:
            sev = "high" if scores["risk"] >= 80 or scores["duplication_pct"] >= 95 else "med"
            Flag.objects.create(event=event, severity=sev, reasons=reasons)

    return ar
