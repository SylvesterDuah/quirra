# analysis/index.py
from __future__ import annotations
import logging
import threading
from typing import List, Optional

logger = logging.getLogger(__name__)

try:
    from datasketch import MinHash, MinHashLSH
    _HAS_DATASKETCH = True
except ImportError:
    _HAS_DATASKETCH = False

# How many existing events to load on cold start
_WARMUP_LIMIT = 5_000
_NUM_PERM     = 128
_THRESHOLD    = 0.5   # Jaccard threshold for LSH bucketing


class _NullIndex:
    """No-op index used when datasketch is unavailable."""
    available = False

    def query(self, sig) -> List[str]:
        return []

    def insert(self, key: str, sig) -> None:
        pass

    def warmup(self) -> None:
        pass


class _LSHIndex:
    available = True

    def __init__(self):
        self._lock  = threading.Lock()
        self._lsh   = MinHashLSH(threshold=_THRESHOLD, num_perm=_NUM_PERM)
        self._keys: set[str] = set()
        self._warmed = False

    # ---------------------------------------------------------------- public

    def query(self, sig: "MinHash") -> List[str]:
        with self._lock:
            try:
                return self._lsh.query(sig)
            except Exception:
                return []

    def insert(self, key: str, sig: "MinHash") -> None:
        with self._lock:
            if key in self._keys:
                return
            try:
                self._lsh.insert(key, sig)
                self._keys.add(key)
            except Exception as exc:
                logger.debug("LSH insert failed for %s: %s", key, exc)

    def warmup(self) -> None:
        """Load recent events from DB into the index on first use."""
        if self._warmed:
            return
        self._warmed = True 
        try:
            self._do_warmup()
        except Exception as exc:
            logger.warning("LSH warmup failed: %s", exc)

    # ---------------------------------------------------------------- private

    def _do_warmup(self) -> None:
        from events.models import Event
        from analysis.algorithm import tokens, shingles, minhash_signature

        qs = (
            Event.objects
            .filter(kind="response")
            .exclude(content=None)
            .order_by("-created_at")
            [:_WARMUP_LIMIT]
        )
        loaded = 0
        for ev in qs:
            toks = tokens(ev.content or "")
            sh   = {" ".join(s) for s in shingles(toks, 3)}
            sig  = minhash_signature(sh, num_perm=_NUM_PERM)
            if sig is not None:
                self.insert(str(ev.pk), sig)
                loaded += 1

        logger.info("LSH index warmed up with %d events", loaded)


def _build_index():
    if _HAS_DATASKETCH:
        return _LSHIndex()
    logger.info("datasketch not installed — LSH index disabled, falling back to SimHash scan")
    return _NullIndex()

lsh_index = _build_index()