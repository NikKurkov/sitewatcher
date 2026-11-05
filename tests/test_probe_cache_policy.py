import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sitewatcher import storage


def test_cache_persists_coalesces_and_partitions():
    from sitewatcher import probe_cache

    calls = []

    async def fetch():
        calls.append(1)
        await asyncio.sleep(.01)
        return {'answer': 'ok'}

    async def exercise():
        results = await asyncio.gather(*[
            probe_cache.get_or_fetch('dnsbl', 'one', fetch) for _ in range(8)
        ])
        assert sum(not result.cached for result in results) == 1
        assert (await probe_cache.get_or_fetch('dnsbl', 'one', fetch)).cached
        assert (await probe_cache.get_or_fetch('tls', 'one', fetch)).cached is False
        assert (await probe_cache.get_or_fetch('dnsbl', 'two', fetch)).cached is False

    asyncio.run(exercise())
    assert len(calls) == 3
    # A fresh event loop has no in-memory task/cache state.
    assert asyncio.run(probe_cache.get_or_fetch('dnsbl', 'one', fetch)).cached
    assert len(calls) == 3


def test_expiry_seed_and_force_debounce():
    from sitewatcher import probe_cache

    async def fetch():
        return {'answer': 'new'}

    old = datetime.now(timezone.utc) - timedelta(seconds=120)
    probe_cache.seed('test', 'one', {'answer': 'old'}, fetched_at=old, ttl_s=86400)
    probe_cache.seed('test', 'one', {'answer': 'overwrite'}, fetched_at=old, ttl_s=86400)
    assert probe_cache.read('test', 'one').value['answer'] == 'old'
    forced = asyncio.run(probe_cache.get_or_fetch('test', 'one', fetch, force=True))
    assert forced.value == {'answer': 'new'}
    assert not forced.cached
    assert asyncio.run(probe_cache.get_or_fetch('test', 'one', fetch, force=True)).cached
    with storage._write_connection() as conn:
        conn.execute('UPDATE probe_cache SET expires_at=0')
    assert not asyncio.run(probe_cache.get_or_fetch('test', 'one', fetch)).cached


def test_cancellation_releases_claim_and_force_does_not_duplicate():
    from sitewatcher import probe_cache

    async def exercise():
        entered = asyncio.Event()
        calls = []

        async def blocked():
            calls.append(1)
            entered.set()
            await asyncio.Event().wait()

        leader = asyncio.create_task(probe_cache.get_or_fetch('test', 'one', blocked))
        await entered.wait()
        follower = asyncio.create_task(probe_cache.get_or_fetch('test', 'one', blocked, force=True))
        await asyncio.sleep(.02)
        assert len(calls) == 1
        leader.cancel()
        with pytest.raises(asyncio.CancelledError):
            await leader
        follower.cancel()
        with pytest.raises(asyncio.CancelledError):
            await follower
        assert probe_cache.read('test', 'one') is None
        assert not (await probe_cache.get_or_fetch('test', 'one', lambda: asyncio.sleep(
            0, result={'ok': True}))).cached

    asyncio.run(exercise())


def test_failed_payload_has_persistent_force_proof_cooldown():
    from sitewatcher import probe_cache

    async def failure():
        return {'error': 'Timeout'}

    first = asyncio.run(probe_cache.get_or_fetch('test', 'one', failure, ttl_s=900))
    assert first.expires_at - first.fetched_at == timedelta(seconds=900)
    again = asyncio.run(probe_cache.get_or_fetch('test', 'one', failure, force=True))
    assert again.cached
    assert first.fetched_at == again.fetched_at


def test_force_waits_for_refresh_instead_of_returning_old_success():
    from sitewatcher import probe_cache

    probe_cache.seed('test', 'one', {'answer': 'old'}, fetched_at=(
        datetime.now(timezone.utc) - timedelta(seconds=120)), ttl_s=86400)

    async def exercise():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def fetch():
            entered.set()
            await release.wait()
            return {'answer': 'new'}

        leader = asyncio.create_task(probe_cache.get_or_fetch('test', 'one', fetch, force=True))
        await entered.wait()
        follower = asyncio.create_task(probe_cache.get_or_fetch('test', 'one', fetch, force=True))
        await asyncio.sleep(.12)
        assert not follower.done()
        release.set()
        first, second = await asyncio.gather(leader, follower)
        assert first.value == second.value == {'answer': 'new'}
        assert second.cached

    asyncio.run(exercise())


def test_abandoned_lease_and_fetch_timeout_are_recoverable(monkeypatch):
    from sitewatcher import probe_cache

    probe_cache.seed('test', 'one', {'answer': 'old'}, fetched_at=(
        datetime.now(timezone.utc) - timedelta(days=2)), ttl_s=86400)
    with storage._write_connection() as conn:
        conn.execute("UPDATE probe_cache SET claim_token='dead-process', claim_until=1")
    monkeypatch.setattr(probe_cache, '_FETCH_TIMEOUT_S', .01)

    async def blocked():
        await asyncio.Event().wait()

    with pytest.raises(TimeoutError):
        asyncio.run(probe_cache.get_or_fetch('test', 'one', blocked))
    assert probe_cache.read('test', 'one').value == {'answer': 'old'}
    renewed = asyncio.run(probe_cache.get_or_fetch(
        'test', 'one', lambda: asyncio.sleep(0, result={'answer': 'new'})))
    assert renewed.value == {'answer': 'new'}


def test_claim_coalesces_across_python_processes(tmp_path):
    import subprocess
    import sys
    from sitewatcher import probe_cache

    # Initialize schema before starting independent interpreters.
    assert probe_cache.read('test', 'one') is None
    marker = tmp_path / 'network-calls'
    script = '''
import asyncio
from pathlib import Path
import sys
from sitewatcher import storage, probe_cache
storage.DEFAULT_DB = Path(sys.argv[1])
async def fetch():
    with open(sys.argv[2], 'a') as stream:
        stream.write('network call\\n')
    await asyncio.sleep(.2)
    return {'answer': 'ok'}
assert asyncio.run(probe_cache.get_or_fetch('test', 'one', fetch)).value == {'answer':'ok'}
'''
    processes = [subprocess.Popen([sys.executable, '-c', script, str(storage.DEFAULT_DB),
                                   str(marker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for _ in range(3)]
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, (stdout, stderr)
    assert marker.read_text().splitlines() == ['network call']
