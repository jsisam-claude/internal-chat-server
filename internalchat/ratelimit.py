"""Sliding-window rate limiter with key eviction (bounded memory)."""
from __future__ import annotations

import threading
import time

from .errors import ApiError

class RateLimiter:
    """Sliding-window limiter. Keys are evicted once their window empties and
    the whole table is capped, so an attacker cannot grow the process heap by
    sending an endless stream of distinct keys (e.g. unknown usernames)."""

    # A full table is rescanned for reclaimable keys at most this often. The
    # scan is O(max_keys) under the lock that serializes every request through
    # this limiter — measured at 1.8 ms per call with the shipped 20k keys,
    # against 1.4 us on the normal path — so running it on every refused check
    # made the refusal cost the very thing the refusal exists to avoid. A
    # window is hundreds of seconds; delaying reclamation by one second cannot
    # matter.
    EVICT_INTERVAL = 1.0

    def __init__(self, limit: int = 10, window: float = 300,
                 max_keys: int = 20_000):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}
        self._last_evict = 0.0

    def check(self, key: str) -> None:
        # MONOTONIC: a window is an interval. On the wall clock a backward
        # step (VM snapshot resume, an NTP step) leaves every recorded hit
        # dated in the future, so a key that had just filled its window stays
        # 429 for the whole step — minutes or hours of "too many attempts" for
        # a user who did nothing. Stamps are internal and never published.
        now = time.monotonic()
        with self._lock:
            if key not in self._hits and len(self._hits) >= self.max_keys:
                # Table full: drop every key whose window has fully expired —
                # at most once per EVICT_INTERVAL, so the scan is amortized
                # instead of paid by every refused check (see EVICT_INTERVAL).
                if now - self._last_evict >= self.EVICT_INTERVAL:
                    self._last_evict = now
                    for k in [k for k, v in self._hits.items()
                              if not v or now - v[-1] >= self.window]:
                        del self._hits[k]
                # If it is STILL full, every key is live. Admitting this one
                # anyway broke the documented bound (the table grew without
                # limit). Refuse instead: under that much pressure the caller
                # IS the flood.
                if len(self._hits) >= self.max_keys:
                    raise ApiError(429, "too many attempts, slow down")
            q = self._hits.setdefault(key, [])
            q[:] = [t for t in q if now - t < self.window]
            if len(q) >= self.limit:
                raise ApiError(429, "too many attempts, slow down")
            q.append(now)

    def sweep(self) -> None:
        """Drop empty/expired keys — called periodically by the janitor so an
        idle server releases limiter memory even below max_keys."""
        now = time.monotonic()   # same clock the stamps were taken on
        with self._lock:
            for k in [k for k, v in self._hits.items()
                      if not v or now - v[-1] >= self.window]:
                del self._hits[k]

