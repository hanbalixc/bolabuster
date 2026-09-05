"""Synchroner Token-Bucket-RateLimiter fuer die Engine.

`TokenBucketLimiter.acquire()` blockiert, bis ein Token frei ist. Zeit- und
Sleep-Funktion sind injizierbar (`clock`, `sleep`), damit Tests eine
Fake-Clock verwenden koennen und nie real schlafen muessen: die Fake-`sleep`
implementiert im Test das Voranschreiten der Fake-`clock`, `acquire()` selbst
enthaelt keine echte Zeitlogik ausser den injizierten Callables.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol


class RateLimiter(Protocol):
    def acquire(self) -> None: ...  # blockiert bis Token frei


@dataclass
class TokenBucketLimiter:
    """Klassischer Token-Bucket: Rate `rate_per_sec`, Kapazitaet `capacity`.

    Kapazitaet default = `max(1.0, rate_per_sec)`, d.h. bei rate < 1/s ist
    trotzdem sofort mindestens ein Token verfuegbar (kein Deadlock beim
    ersten Aufruf), bei rate >= 1/s erlaubt die Kapazitaet einen Burst von
    bis zu einer Sekunde angesammelter Requests.
    """

    rate_per_sec: float
    capacity: float | None = None
    clock: Callable[[], float] = field(default=time.monotonic)
    sleep: Callable[[float], None] = field(default=time.sleep)
    _tokens: float = field(init=False, repr=False)
    _last: float = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.rate_per_sec <= 0:
            raise ValueError(f"rate_per_sec muss > 0 sein, war {self.rate_per_sec!r}")
        if self.capacity is None:
            self.capacity = max(1.0, self.rate_per_sec)
        self._tokens = self.capacity
        self._last = self.clock()

    def acquire(self) -> None:
        while True:
            now = self.clock()
            elapsed = now - self._last
            self._last = now
            if elapsed > 0:
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            deficit = 1.0 - self._tokens
            wait = deficit / self.rate_per_sec
            self.sleep(wait)


@dataclass
class NullLimiter:
    """No-Op-Limiter fuer Dry-Run/Tests, wo keine Drosselung noetig ist."""

    def acquire(self) -> None:
        return None
