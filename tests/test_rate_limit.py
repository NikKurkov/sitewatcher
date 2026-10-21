"""Offline quota checks with an injected clock and explicitly controlled waiters."""
import asyncio

import pytest

from sitewatcher.utils import rate_limit
from sitewatcher.utils.rate_limit import MultiWindowRateLimiter, Window


@pytest.fixture
def clock(monkeypatch):
    now = [100000.0]
    monkeypatch.setattr(rate_limit.time, 'time', lambda: now[0])
    return now


def test_simultaneous_acquires_respect_minute_day_and_month_windows(clock):
    async def exercise():
        limiter = MultiWindowRateLimiter([
            Window(60, 4), Window(86400, 6), Window(30 * 86400, 8),
        ])

        async def burst():
            results = await asyncio.gather(*(limiter.try_acquire() for _ in range(40)))
            return sum(acquired for acquired, _ in results)

        assert await burst() == 4
        clock[0] += 60
        assert await burst() == 2  # The day quota caps this minute.
        clock[0] += 86400
        assert await burst() == 2  # The month quota caps this day.
        clock[0] += 30 * 86400
        assert await burst() == 4

    asyncio.run(exercise())


@pytest.mark.parametrize('seconds', [60, 86400, 30 * 86400])
def test_slot_frees_at_exact_window_boundary(clock, seconds):
    async def exercise():
        limiter = MultiWindowRateLimiter([Window(seconds, 1)])
        assert await limiter.try_acquire() == (True, 0.0)
        started = clock[0]
        clock[0] = started + seconds - 0.25
        assert await limiter.try_acquire() == (False, 0.25)
        clock[0] = started + seconds
        assert await limiter.try_acquire() == (True, 0.0)
        assert await limiter.try_acquire() == (False, seconds)

    asyncio.run(exercise())


def test_insufficient_wait_budget_returns_delay_without_consuming_quota(clock, monkeypatch):
    async def forbidden_sleep(delay):
        raise AssertionError('A delay beyond the wait budget must not sleep')

    monkeypatch.setattr(rate_limit.asyncio, 'sleep', forbidden_sleep)

    async def exercise():
        limiter = MultiWindowRateLimiter([Window(60, 1), Window(86400, 2)])
        assert await limiter.try_acquire() == (True, 0.0)
        assert await limiter.try_acquire(max_wait_s=59) == (False, 60)
        clock[0] += 60
        assert await limiter.try_acquire() == (True, 0.0)
        assert await limiter.try_acquire() == (False, 86340)

    asyncio.run(exercise())


def test_bounded_waiters_recheck_atomically_after_racing_for_one_slot(clock, monkeypatch):
    async def exercise():
        limiter = MultiWindowRateLimiter([Window(60, 1), Window(86400, 3)])
        assert await limiter.try_acquire() == (True, 0.0)
        waiting = asyncio.Event()
        resume = asyncio.Event()
        sleeper_count = 0

        async def controlled_sleep(delay):
            nonlocal sleeper_count
            assert delay == 60
            sleeper_count += 1
            if sleeper_count == 2:
                waiting.set()
            await resume.wait()

        monkeypatch.setattr(rate_limit.asyncio, 'sleep', controlled_sleep)
        first = asyncio.create_task(limiter.try_acquire(max_wait_s=60))
        second = asyncio.create_task(limiter.try_acquire(max_wait_s=60))
        await waiting.wait()
        clock[0] += 60
        resume.set()
        results = await asyncio.gather(first, second)
        assert sorted(results) == [(False, 60), (True, 60)]
        clock[0] += 60
        assert await limiter.try_acquire() == (True, 0.0)
        assert await limiter.try_acquire() == (False, 86280)

    asyncio.run(exercise())


def test_cancelled_waiter_does_not_consume_any_window_allowance(clock, monkeypatch):
    async def exercise():
        limiter = MultiWindowRateLimiter([Window(60, 1), Window(86400, 2)])
        assert await limiter.try_acquire() == (True, 0.0)
        waiting = asyncio.Event()
        resume = asyncio.Event()

        async def controlled_sleep(delay):
            waiting.set()
            await resume.wait()

        monkeypatch.setattr(rate_limit.asyncio, 'sleep', controlled_sleep)
        task = asyncio.create_task(limiter.try_acquire(max_wait_s=60))
        await waiting.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        clock[0] += 60
        assert await limiter.try_acquire() == (True, 0.0)
        assert await limiter.try_acquire() == (False, 86340)

    asyncio.run(exercise())
