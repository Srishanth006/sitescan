from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token bucket shared by every scanner in a run.

    Every outbound request/connection to the target calls ``await acquire()``,
    so the *global* request rate never exceeds ``rate`` per second no matter
    how many scanners run concurrently. Burst is capped at ``rate`` tokens
    (min 1) so a fresh bucket can't fire more than one second's worth at once.
    """

    def __init__(self, rate: float):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = max(1.0, self.rate)
        self._tokens = 1.0  # start nearly empty: no initial burst
        self._last = time.monotonic()
        self._lock = asyncio.Lock()
        self.total = 0

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rate
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self.total += 1
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate)
