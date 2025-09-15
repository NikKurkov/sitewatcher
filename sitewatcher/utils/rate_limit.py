# sitewatcher/utils/rate_limit.py
from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Tuple


@dataclass(frozen=True)
class Window:
    """Sliding window definition."""
    seconds: int
    limit: int


class MultiWindowRateLimiter:
    """
    Async, process-local, sliding-window rate limiter for multiple windows at once.
    Intended for small quotas like VirusTotal Free (4/min, 500/day, 15500/month).

    Notes:
      - Uses epoch time (time.time()) to enforce real-time windows (minute/day/month).
      - Keeps only timestamps needed to decide (O(1) append/left-pop amortized).
      - Safe for concurrent use via an internal asyncio.Lock.
      - Not persistent across process restarts.
    """

    def __init__(self, windows: Iterable[Window]) -> None:
        """
        Args:
            windows: Iterable of Window(seconds, limit). For VT Free you might pass:
                     [Window(60, 4), Window(24*3600, 500), Window(30*24*3600, 15500)]
                     (month approximated as 30 days).
        """
        self._windows = list(sorted(windows, key=lambda w: w.seconds))
        self._events: Dict[int, Deque[float]] = {w.seconds: deque() for w in self._windows}
        self._lock = asyncio.Lock()

    # ---------------- public API ----------------

    async def try_acquire(self, *, max_wait_s: float = 0.0) -> Tuple[bool, float]:
        """
        Try to acquire a slot; optionally wait up to max_wait_s for the earliest window to free a slot.

        Returns:
            (acquired, waited_or_needed)
                - If acquired == True: second value is how long we actually waited (float seconds).
                - If acquired == False: second value is the minimal delay (float seconds) needed right now.

        Behavior:
            - If all windows have room, records the event and returns (True, 0.0).
            - Else computes the minimal required delay across windows. If delay <= max_wait_s:
              sleeps that long, re-checks atomically, records the event, returns (True, waited).
            - Else returns (False, delay).
        """
        start = time.time()
        async with self._lock:
            delay = self._needed_delay_locked(start)
            if delay <= 0.0:
                self._record_locked(start)
                return True, 0.0

        # Outside the lock to avoid blocking others while we wait
        if delay <= max_wait_s:
            await asyncio.sleep(delay)
            waited = time.time() - start
            async with self._lock:
                # Re-check after sleeping in case other coroutines consumed slots
                now = time.time()
                delay2 = self._needed_delay_locked(now)
                if delay2 <= 0.0:
                    self._record_locked(now)
                    return True, waited
                # Not enough even after sleeping: report remaining delay; do not wait further.
                return False, delay2

        return False, delay

    # ---------------- internals ----------------

    def _cleanup_locked(self, now: float) -> None:
        """Drop timestamps outside their window (must be called with lock held)."""
        for w in self._windows:
            dq = self._events[w.seconds]
            cutoff = now - w.seconds
            while dq and dq[0] <= cutoff:
                dq.popleft()

    def _needed_delay_locked(self, now: float) -> float:
        """
        Compute minimal delay required across windows to not exceed limits.
        Returns 0 if no delay needed; otherwise a positive float seconds.
        """
        self._cleanup_locked(now)
        needed = 0.0
        for w in self._windows:
            dq = self._events[w.seconds]
            if len(dq) < w.limit:
                continue
            # Next slot in this window becomes available when the oldest event expires
            oldest = dq[0]
            delay = (oldest + w.seconds) - now
            if delay > needed:
                needed = delay
        return max(0.0, needed)

    def _record_locked(self, ts: float) -> None:
        """Record an event timestamp across all windows (must be called with lock held)."""
        for w in self._windows:
            self._events[w.seconds].append(ts)
