"""Sliding-window rate limiter with key eviction (bounded memory)."""
from __future__ import annotations

import threading
import time

from .errors import ApiError

class RateLimiter:
    """Sliding-window limiter. Keys are evicted once their window empties and
    the whole table is capped, so an attacker cannot grow the process heap by
    sending an endless stream of distinct keys (e.g. unknown usernames)."""

    def __init__(self, limit: int = 10, window: float = 300,
                 max_keys: int = 20_000):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> None:
        now = time.time()
        with self._lock:
            if key not in self._hits and len(self._hits) >= self.max_keys:
                # table full: drop every key whose window has fully expired
                for k in [k for k, v in self._hits.items()
                          if not v or now - v[-1] >= self.window]:
                    del self._hits[k]
            q = self._hits.setdefault(key, [])
            q[:] = [t for t in q if now - t < self.window]
            if len(q) >= self.limit:
                raise ApiError(429, "too many attempts, slow down")
            q.append(now)

    def sweep(self) -> None:
        """Drop empty/expired keys — called periodically by the janitor so an
        idle server releases limiter memory even below max_keys."""
        now = time.time()
        with self._lock:
            for k in [k for k, v in self._hits.items()
                      if not v or now - v[-1] >= self.window]:
                del self._hits[k]

