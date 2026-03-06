# analysis/engine.py

from __future__ import annotations

import logging
from typing import Any

from events.models import Event
from flags.models import Flag
from analysis.models import AnalysisResult

from analysis.algorithm import (
    tokens,
    shingles,
    jaccard,
    simhash64,
    hamming64,
    minhash_signature,
    style_sameness_score,
    risk_score,
    fused_duplication_pct,
    label_from_similarity,
    Similarity,
)

from analysis.index import lsh_index

logger = logging.getLogger(__name__)

_JACCARD_NEIGHBOUR = 0.80   
_HAMMING_PREFILTER = 12     
_SCAN_LIMIT        = 1_000  
_MAX_NEIGHBORS     = 10     
_NUM_PERM          = 128    


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _shingle_set(text: str, k: int = 3) -> set:
    """Return a set of k-gram tuples for Jaccard computation."""
    return set(shingles(tokens(text or ""), k))


def _uint64_to_signed(n: int) -> int:
    """Convert unsigned 64-bit int to Python signed int for BigIntegerField storage."""
    if n >= (1 << 63):
        return n - (1 << 64)
    return n


def _signed_to_uint64(n: int) -> int:
    """Reverse the signed→unsigned conversion when reading back from DB."""
    if n < 0:
        return n + (1 << 64)
    return n


# ------------------------------------------------------------------
# Neighbour search strategies
# ------------------------------------------------------------------

def _search_via_lsh(
    event: Event,
    sh_a: set,
    toks_a: list[str],
    sh_strings: set[str],
) -> tuple[list[dict[str, Any]], float, int]:
    """
    Strategy 1: MinHash LSH approximate nearest-neighbour lookup.
    Returns (neighbors, top_sim, seen_count).
    """
    sig_a = minhash_signature(sh_strings, num_perm=_NUM_PERM)
    if sig_a is None:
        return [], 0.0, 0


    lsh_index.warmup()

    candidate_ids = lsh_index.query(sig_a)
    if not candidate_ids:
        return [], 0.0, 0

    neighbors   = []
    top_sim     = 0.0
    seen_count  = 0

    candidates = Event.objects.filter(pk__in=candidate_ids).exclude(pk=event.pk)
    for other in candidates:
        sh_b = _shingle_set(other.content or "")
        sim  = jaccard(sh_a, sh_b)
        top_sim = max(top_sim, sim)
        if sim >= _JACCARD_NEIGHBOUR:
            seen_count += 1
            neighbors.append(_make_neighbor(other, sim))
        if len(neighbors) >= _MAX_NEIGHBORS:
            break

    return neighbors, top_sim, seen_count


def _search_via_simhash(
    event: Event,
    sh_a: set,
    hash_a: int,
) -> tuple[list[dict[str, Any]], float, int]:
    """
    Strategy 2: SimHash Hamming pre-filter then Jaccard rerank.
    """
    qs = (
        Event.objects
        .filter(kind="response")
        .exclude(pk=event.pk)
        .exclude(simhash=None)
    )
    if getattr(event, "project_id", None):
        qs = qs.filter(project_id=event.project_id)

    neighbors  = []
    top_sim    = 0.0
    seen_count = 0

    for other in qs.order_by("-created_at")[:_SCAN_LIMIT]:
        hash_b   = _signed_to_uint64(other.simhash)
        distance = hamming64(hash_a, hash_b)
        if distance > _HAMMING_PREFILTER:
            continue 
        sh_b = _shingle_set(other.content or "")
        sim  = jaccard(sh_a, sh_b)
        top_sim = max(top_sim, sim)
        if sim >= _JACCARD_NEIGHBOUR:
            seen_count += 1
            neighbors.append(_make_neighbor(other, sim))
        if len(neighbors) >= _MAX_NEIGHBORS:
            break

    return neighbors, top_sim, seen_count


def _search_sequential(
    event: Event,
    sh_a: set,
) -> tuple[list[dict[str, Any]], float, int]:
    """
    Strategy 3: plain sequential Jaccard scan (original behaviour).
    """
    qs = Event.objects.filter(kind="response").exclude(pk=event.pk)
    if getattr(event, "project_id", None):
        qs = qs.filter(project_id=event.project_id)

    neighbors  = []
    top_sim    = 0.0
    seen_count = 0

    for other in qs.order_by("-created_at")[:_SCAN_LIMIT]:
        sh_b = _shingle_set(other.content or "")
        sim  = jaccard(sh_a, sh_b)
        top_sim = max(top_sim, sim)
        if sim >= _JACCARD_NEIGHBOUR:
            seen_count += 1
            neighbors.append(_make_neighbor(other, sim))
        if len(neighbors) >= _MAX_NEIGHBORS:
            break

    return neighbors, top_sim, seen_count


def _make_neighbor(other: Event, sim: float) -> dict[str, Any]:
    return {
        "event_id":  str(other.pk),
        "when":      other.created_at.isoformat(),
        "context":   (other.metadata or {}).get("context"),
        "url":       (other.metadata or {}).get("url"),
        "similarity": round(sim, 3),
    }


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------

def compute_analysis(event: Event) -> AnalysisResult:
    """
    Compute and persist analysis for a single Event.

    For prompts : style + risk only (no duplicate search).
    For responses: duplicate search (LSH → SimHash → sequential), style, risk, labels.
    """
    text     = (event.content or "").strip()
    toks     = tokens(text)
    is_prompt = (event.kind == "prompt")

    # --- Compute and store SimHash on the Event itself ---------------
    sh_strings = {" ".join(s) for s in shingles(toks, 3)}
    hash_int   = simhash64(sh_strings) if sh_strings else None

    if hash_int is not None:
        signed = _uint64_to_signed(hash_int)
        if event.simhash != signed:
            Event.objects.filter(pk=event.pk).update(simhash=signed)
            event.simhash = signed

    # --- Duplicate / neighbour search (responses only) ---------------
    if is_prompt:
        neighbors  = []
        top_sim    = 0.0
        seen_count = 0
    else:
        sh_a = set(shingles(toks, 3))  # set of tuples for jaccard()

        # Try strategies in order of speed
        if lsh_index.available:
            neighbors, top_sim, seen_count = _search_via_lsh(
                event, sh_a, toks, sh_strings
            )
        elif hash_int is not None:
            neighbors, top_sim, seen_count = _search_via_simhash(
                event, sh_a, hash_int
            )
        else:
            neighbors, top_sim, seen_count = _search_sequential(event, sh_a)

        if lsh_index.available and sh_strings:
            sig = minhash_signature(sh_strings, num_perm=_NUM_PERM)
            if sig is not None:
                lsh_index.insert(str(event.pk), sig)

    # --- Style & risk ------------------------------------------------
    style_same = style_sameness_score(toks)
    duplication = max(0.0, min(1.0, top_sim))
    duplication_pct = int(round(duplication * 100))
    risk = risk_score(text, duplication_pct)

    # --- Build similarity object for labelling -----------------------
    hamming = None
    if hash_int is not None and neighbors:
        # Compute Hamming against the closest neighbour for the label
        try:
            closest_id  = neighbors[0]["event_id"]
            closest_ev  = Event.objects.get(pk=closest_id)
            if closest_ev.simhash is not None:
                hamming = hamming64(hash_int, _signed_to_uint64(closest_ev.simhash))
        except Exception:
            pass

    sim_obj = Similarity(
        jaccard=top_sim,
        hamming=hamming,
    )
    dup_pct_fused = fused_duplication_pct(sim_obj)
    label         = label_from_similarity(sim_obj)

    # --- Scores dict -------------------------------------------------
    scores = {
        "duplication_pct": dup_pct_fused,
        "style_pct":       int(round(style_same * 100)),
        "risk":            int(risk),
        "seen_count":      int(seen_count),
        "kind":            event.kind,
    }

    # --- Labels list -----------------------
    labels: list[str] = []
    if label != "dissimilar":
        labels.append(f"duplicate:{label}")
    if scores["style_pct"] >= 70:
        labels.append("style:repetitive")
    if scores["risk"] >= 70:
        labels.append("risk:high")
    elif scores["risk"] >= 40:
        labels.append("risk:medium")

    # --- Persist AnalysisResult --------------------------------------
    ar, _ = AnalysisResult.objects.update_or_create(
        event=event,
        defaults={
            "scores":    scores,
            "neighbors": neighbors,
            "labels":    labels,
        },
    )

    # --- Auto-flag ----------------------------------
    if not is_prompt:
        reasons = []
        if scores["duplication_pct"] >= 90:
            reasons.append("duplication-high")
        if scores["seen_count"] >= 3:
            reasons.append("seen-many")
        if scores["risk"] >= 70:
            reasons.append("policy-risk")
        if scores["style_pct"] >= 70:
            reasons.append("style-repetitive")

        if reasons:
            sev = "high" if (scores["risk"] >= 80 or scores["duplication_pct"] >= 95) else "med"
            Flag.objects.create(event=event, severity=sev, reasons=reasons)

    return ar