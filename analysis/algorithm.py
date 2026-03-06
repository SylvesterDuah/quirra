# analysis/algorithm.py
from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass
from typing import List, Iterable, Tuple, Optional

try:
    import blake3 as _blake3
    def _hash_bytes(s: str) -> bytes:
        return _blake3.blake3(s.encode("utf-8")).digest()
except Exception:
    def _hash_bytes(s: str) -> bytes:
        return hashlib.sha256(s.encode("utf-8")).digest()

try:
    from datasketch import MinHash, MinHashLSH
    HAS_MINHASH = True
except Exception:
    HAS_MINHASH = False

try:
    import numpy as np
    HAS_NUMPY = True
except Exception:
    HAS_NUMPY = False


# ---------------------------------------------------------------------------
# Text normalisation & tokenisation
# ---------------------------------------------------------------------------

SPACE_RE = re.compile(r"\s+")
WORD_RE  = re.compile(r"[A-Za-z0-9']+", re.UNICODE)


def normalize_text(s: str) -> str:
    return SPACE_RE.sub(" ", (s or "").strip())


def tokens(s: str) -> List[str]:
    return WORD_RE.findall((s or "").lower())


def shingles(words: List[str], k: int = 3) -> List[Tuple[str, ...]]:
    if len(words) < k:
        return []
    return [tuple(words[i:i + k]) for i in range(len(words) - k + 1)]


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def blake3_hex(s: str) -> str:
    return _hash_bytes(s).hex()


def simhash64(features: Iterable[str]) -> int:
    """
    64-bit SimHash over an iterable of string features (unweighted).

    Bug that was here before: the original code called
        blake3_hex(f).encode("ascii")[:16]
    which re-encodes the hex *string* back to ASCII bytes.  Those bytes are
    drawn from {0x30-0x39, 0x61-0x66} only, so bits 7, 6, 5 of every byte
    are nearly constant — the resulting SimHash was useless for Hamming
    distance comparisons.
    """
    v = [0] * 64
    for f in features:
        raw = _hash_bytes(f)
        h   = int.from_bytes(raw[:8], "big", signed=False)
        for i in range(64):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming64(a: int, b: int) -> int:
    """Kernighan bit-count popcount for XOR of two 64-bit integers."""
    x = a ^ b
    c = 0
    while x:
        x &= x - 1
        c += 1
    return c


# ---------------------------------------------------------------------------
# MinHash (Jaccard via LSH)
# ---------------------------------------------------------------------------

def minhash_signature(items: Iterable[str], num_perm: int = 128) -> Optional["MinHash"]:
    if not HAS_MINHASH:
        return None
    m = MinHash(num_perm=num_perm)
    for it in items:
        m.update(it.encode("utf-8"))
    return m


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / (len(a | b) or 1)


# ---------------------------------------------------------------------------
# Style features
# ---------------------------------------------------------------------------

FUNCTION_WORDS = set("""
a about above after again against all am an and any are as at be because been before being below
between both but by can could did do does doing down during each few for from further had has
have having he her here hers herself him himself his how i if in into is it its itself just me
more most my myself no nor not of off on once only or other our ours ourselves out over own same
she should so some such than that the their theirs them themselves then there these they this those
through to too under until up very was we were what when where which while who whom why with you
your yours yourself yourselves
""".split())


def style_sameness_score(words: List[str]) -> float:
    """
    Returns a [0, 1] score where 1 = maximally repetitive/formulaic.
    Combines type-token ratio, average sentence length, and function-word density.
    """
    if not words:
        return 0.0
    ttr        = len(set(words)) / max(1, len(words))
    avg_sent   = avg_sentence_len(" ".join(words))
    func_ratio = sum(1 for w in words if w in FUNCTION_WORDS) / len(words)

    ttr_comp  = 1.0 - ttr                                      
    sent_comp = min(1.0, max(0.0, (avg_sent - 18) / 18))     
    func_comp = max(0.0, func_ratio - 0.45) * 2.0

    return max(0.0, min(1.0, 0.55 * ttr_comp + 0.25 * sent_comp + 0.20 * func_comp))


def avg_sentence_len(text: str) -> float:
    parts = re.split(r"[.!?]+", text)
    lens  = [len(WORD_RE.findall(p)) for p in parts if WORD_RE.findall(p)]
    return sum(lens) / len(lens) if lens else 0.0


# ---------------------------------------------------------------------------
# Policy & risk scoring  (canonical — import this, do not re-implement)
# ---------------------------------------------------------------------------

POLICY_TERMS: dict[str, list[str]] = {
    "misuse": [
        "bypass", "jailbreak", "exploit", "xss", "sql injection", "phishing",
        "malware", "crack", "warez", "pirated", "keygen",
        "weapon", "bomb", "poison", "harm", "kill", "deepfake",
    ],
    "privacy": ["dox", "leak", "private data", "pii", "password", "token"],
    "bias":    ["stereotype", "bias", "hate", "racist", "sexist"],
}

LM_TELLS = ["as an ai", "as a language model", "cannot assist with that"]


def risk_score(text: str, duplication_pct: int) -> int:
    """
    Returns an integer risk score in [0, 100].

    Factors:
      - duplication_pct: high repetition correlates with policy evasion
      - POLICY_TERMS category hits (one point per category matched)
      - explicit jailbreak language (+25)
      - LLM refusal tells in a response (+10, signals the model was pushed)
    """
    t         = (text or "").lower()
    hits      = sum(1 for words in POLICY_TERMS.values() if any(w in t for w in words))
    jailbreak = 1 if ("ignore previous instructions" in t or "bypass" in t or "jailbreak" in t) else 0
    lm_tell   = 1 if any(p in t for p in LM_TELLS) else 0
    base      = (duplication_pct / 100.0) * 60 + hits * 10 + jailbreak * 25 + lm_tell * 10
    return int(max(0, min(100, round(base))))


# ---------------------------------------------------------------------------
# Similarity fusion & labelling
# ---------------------------------------------------------------------------

@dataclass
class Similarity:
    jaccard: float        = 0.0
    hamming: Optional[int] = None
    cosine:  Optional[float] = None


def fused_duplication_pct(sim: Similarity) -> int:
    """Combine all available similarity signals into a single duplication %."""
    parts = [sim.jaccard]
    if sim.hamming is not None:
        parts.append(max(0.0, 1.0 - (sim.hamming / 64.0)))
    if sim.cosine is not None:
        parts.append(sim.cosine)
    return int(round(100 * max(parts)))


def label_from_similarity(sim: Similarity) -> str:
    if sim.jaccard >= 0.98:
        return "exact"
    if (sim.jaccard >= 0.83
            or (sim.hamming is not None and sim.hamming <= 6)
            or (sim.cosine  is not None and sim.cosine  >= 0.93)):
        return "near"
    if (sim.jaccard >= 0.70
            or (sim.hamming is not None and sim.hamming <= 10)
            or (sim.cosine  is not None and sim.cosine  >= 0.88)):
        return "similar"
    return "dissimilar"