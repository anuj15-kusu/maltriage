"""Client-side pacing. The free VirusTotal tier allows 4 requests per minute."""

from __future__ import annotations

import threading
import time


class MinInterval:
    """Block until at least `seconds` have passed since the previous call."""

    def __init__(self, seconds: float) -> None:
        self.seconds = max(0.0, seconds)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> float:
        with self._lock:
            now = time.monotonic()
            remaining = self.seconds - (now - self._last)
            if remaining > 0:
                time.sleep(remaining)
            self._last = time.monotonic()
            return max(0.0, remaining)


class DailyBudget:
    """Simple in-process counter, enough to stop a runaway batch job."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    def spend(self) -> bool:
        with self._lock:
            if self.limit and self.used >= self.limit:
                return False
            self.used += 1
            return True

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)
