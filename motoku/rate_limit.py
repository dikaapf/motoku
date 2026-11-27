"""Small in-memory sliding-window rate limiter.

No external dependency is required. State is process-local, which is fine for
the single-process deployment this app targets; a shared store (Redis) can
replace it later without changing the call sites.
"""

import threading
import time
from collections import defaultdict, deque

_hits = defaultdict(deque)
_lock = threading.Lock()
_blocked_total = 0


def reset():
    global _blocked_total
    with _lock:
        _hits.clear()
        _blocked_total = 0


def check(key, limit, window):
    """Return ``(allowed, retry_after_seconds)`` for ``key``."""
    global _blocked_total
    now = time.time()
    with _lock:
        bucket = _hits[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()

        if len(bucket) >= limit:
            _blocked_total += 1
            retry_after = max(1, int(window - (now - bucket[0])))
            return False, retry_after

        bucket.append(now)
        return True, 0


def stats():
    with _lock:
        return {
            'tracked_clients': len(_hits),
            'blocked_total': _blocked_total,
        }
