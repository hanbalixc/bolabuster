"""Tests fuer den synchronen Token-Bucket-RateLimiter (Fake-Clock, kein echtes Warten)."""

from bolabuster.engine.ratelimit import NullLimiter, TokenBucketLimiter


class FakeClock:
    """Injizierbare Zeit-/Sleep-Quelle: `sleep()` schlaeft nicht real,
    sondern schiebt die Fake-Zeit direkt um die angeforderte Dauer weiter
    und protokolliert die Wartezeiten fuer die Assertions."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_burst_within_capacity_does_not_wait():
    fake = FakeClock()
    limiter = TokenBucketLimiter(rate_per_sec=2.0, clock=fake.time, sleep=fake.sleep)

    limiter.acquire()
    limiter.acquire()

    assert fake.slept == []
    assert fake.now == 0.0


def test_exhausted_bucket_forces_expected_cumulative_wait():
    fake = FakeClock()
    # rate=2/s -> capacity default = max(1, 2) = 2 Token sofort verfuegbar.
    limiter = TokenBucketLimiter(rate_per_sec=2.0, clock=fake.time, sleep=fake.sleep)

    for _ in range(5):
        limiter.acquire()

    # Aufrufe 1+2: aus dem Startguthaben (Kapazitaet=2), kein Warten.
    # Aufrufe 3-5: je ein Token fehlt -> je 1/rate = 0.5s Wartezeit.
    assert fake.slept == [0.5, 0.5, 0.5]
    assert fake.now == 1.5


def test_low_rate_still_grants_first_token_immediately():
    fake = FakeClock()
    # rate=0.5/s -> capacity default = max(1, 0.5) = 1 Token sofort verfuegbar,
    # damit der allererste acquire() nicht blockiert.
    limiter = TokenBucketLimiter(rate_per_sec=0.5, clock=fake.time, sleep=fake.sleep)

    limiter.acquire()
    assert fake.slept == []

    limiter.acquire()
    assert fake.slept == [2.0]
    assert fake.now == 2.0


def test_invalid_rate_rejected():
    fake = FakeClock()
    try:
        TokenBucketLimiter(rate_per_sec=0.0, clock=fake.time, sleep=fake.sleep)
    except ValueError:
        pass
    else:
        raise AssertionError("erwarteter ValueError bei rate_per_sec=0 blieb aus")


def test_null_limiter_never_waits():
    limiter = NullLimiter()
    limiter.acquire()
    limiter.acquire()
    # kein Fehler, kein Sleep noetig - Protokoll-konform (acquire() gibt None zurueck)
    assert limiter.acquire() is None
