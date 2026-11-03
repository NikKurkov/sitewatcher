"""Diagnostics retain owner boundaries and never change availability or alert state."""
import asyncio
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from sitewatcher import check_activity, network_routes as routes, storage
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig


def owned(owner=7, domain='example.com'):
    storage.add_domain(owner, domain)
    return owner, domain


def age(owner=7, domain='example.com', *, seconds=3601, state='ready'):
    stamp = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with closing(storage._connect()) as conn:
        conn.execute('UPDATE domain_routes SET state=?,updated_at=? '
                     'WHERE owner_id=? AND domain=?', (state, stamp, owner, domain))


def fake_probe(monkeypatch, *, reached=True):
    from sitewatcher.checks import traceroute

    class Probe:
        def __init__(self, domain):
            self.domain = domain

        async def run(self):
            return CheckOutcome('traceroute', Status.OK, 'diagnostic', {
                'destination_ip': '192.0.2.1', 'method': 'udp',
                'hops': [{'ttl': 1, 'ip': '192.0.2.1', 'hostname': None, 'rtt_ms': 1.0}],
                'reached': reached, 'truncated': False, 'captured_at': routes._now(),
                'duration_ms': 1,
            })
    monkeypatch.setattr(traceroute, 'TracerouteCheck', Probe)


def test_reads_never_initialize_missing_or_old_storage():
    assert routes.read_owner(7) == {}
    assert not storage.DEFAULT_DB.exists()
    with sqlite3.connect(storage.DEFAULT_DB) as conn:
        conn.execute('CREATE TABLE unrelated(id INTEGER)')
    before = storage.DEFAULT_DB.read_bytes()
    assert routes.read_owner(7) == {}
    assert storage.DEFAULT_DB.read_bytes() == before


def test_owner_isolation_conflict_disable_and_delete_cascade():
    owned()
    owned(8)
    routes.request_trace(7, 'example.com')
    assert routes.read_owner(8) == {}
    with pytest.raises(ValueError):
        routes.request_trace(9, 'example.com')
    with pytest.raises(RuntimeError):
        routes.request_trace(7, 'example.com')
    routes.request_trace(8, 'example.com')
    routes.request_trace(7, 'example.com', enabled=False)
    assert routes.read_owner(7)['example.com']['state'] == 'disabled'
    assert routes.read_owner(8)['example.com']['state'] == 'queued'
    storage.remove_domain(7, 'example.com')
    assert routes.read_owner(7) == {}
    assert routes.read_owner(8)


@pytest.mark.parametrize('reached,state', [(True, 'ready'), (False, 'partial')])
def test_probe_cache_lifecycle_and_availability_alert_isolation(monkeypatch, reached, state):
    owner, domain = owned()
    storage.save_history(owner, domain, 'http_basic', 'OK', 'healthy', {})
    storage.upsert_alert_state(owner, domain, 'OK', None)
    fake_probe(monkeypatch, reached=reached)
    routes.request_trace(owner, domain)
    asyncio.run(routes._execute(owner, domain))
    data = routes.read_owner(owner)[domain]
    assert data['state'] == state
    assert data['result']['reached'] == reached
    assert len(storage.last_results(owner, domain)) == 1
    assert storage.get_alert_state(owner, domain)['last_overall'] == 'OK'
    event = check_activity.recent(owner)[0]
    assert event['check_name'] == 'traceroute' and event['finished_at']
    previous = data['result']
    routes.request_trace(owner, domain)
    assert routes.read_owner(owner)[domain]['result'] == previous
    routes.request_trace(owner, domain, False)
    assert routes.read_owner(owner)[domain]['result'] == previous


def test_hourly_selection_respects_pause_and_global_switch_but_manual_is_prompt():
    owner, domain = owned()
    routes.request_trace(owner, domain)
    cfg = AppConfig()
    cfg.scheduler.enabled = False
    assert routes._candidates(cfg) == [(owner, domain)]
    age()
    assert routes._candidates(cfg) == []
    cfg.scheduler.enabled = True
    storage.set_domain_override(owner, domain, {'interval_minutes': 0})
    assert routes._candidates(cfg) == []
    storage.set_domain_override(owner, domain, {'interval_minutes': 5})
    age(seconds=3590)
    assert routes._candidates(cfg) == []
    age()
    assert routes._candidates(cfg) == [(owner, domain)]


def test_running_lease_recovery_and_cas_disable_delete_races():
    owner, domain = owned()
    routes.request_trace(owner, domain)
    lease = routes._now()
    assert routes._claim(owner, domain, lease)
    assert not routes._claim(owner, domain, routes._now())
    assert routes._candidates(AppConfig()) == []
    age(state='running', seconds=61)
    assert routes._candidates(AppConfig()) == [(owner, domain)]
    new_lease = routes._now()
    assert routes._claim(owner, domain, new_lease)
    routes._persist(owner, domain, lease, 'ready', {'stale': True})
    assert routes.read_owner(owner)[domain]['result'] is None
    routes.request_trace(owner, domain, False)
    routes._persist(owner, domain, new_lease, 'ready', {'stale': True})
    assert routes.read_owner(owner)[domain]['state'] == 'disabled'
    storage.remove_domain(owner, domain)
    owned()
    routes.request_trace(owner, domain)
    routes._persist(owner, domain, new_lease, 'ready', {'stale': True})
    assert routes.read_owner(owner)[domain]['state'] == 'queued'
    assert routes.read_owner(owner)[domain]['result'] is None


def test_failure_preserves_previous_cache(monkeypatch):
    from sitewatcher.checks import traceroute
    owner, domain = owned()
    routes.request_trace(owner, domain)
    with closing(storage._connect()) as conn:
        conn.execute('UPDATE domain_routes SET result_json=?', (json.dumps({'old': True}),))

    class Broken:
        def __init__(self, domain):
            pass

        async def run(self):
            raise OSError('synthetic')
    monkeypatch.setattr(traceroute, 'TracerouteCheck', Broken)
    asyncio.run(routes._execute(owner, domain))
    assert routes.read_owner(owner)[domain]['state'] == 'error'
    assert routes.read_owner(owner)[domain]['result'] == {'old': True}
    assert check_activity.recent(owner)[0]['status'] == 'UNKNOWN'


@pytest.mark.parametrize('cancellations', [1, 2])
def test_runner_drains_probe_on_cancellation_and_marks_unknown(monkeypatch, cancellations):
    from sitewatcher.checks import traceroute
    owned()
    routes.request_trace(7, 'example.com')
    monkeypatch.setattr(routes, 'POLL_SECONDS', 0.01)

    async def scenario():
        entered = asyncio.Event()
        cleaning = asyncio.Event()
        release = asyncio.Event()
        finished = asyncio.Event()

        class Probe:
            def __init__(self, domain):
                pass

            async def run(self):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cleaning.set()
                    await release.wait()
                    finished.set()
        monkeypatch.setattr(traceroute, 'TracerouteCheck', Probe)

        async def worker():
            async with routes.runner(AppConfig()):
                await asyncio.Event().wait()
        task = asyncio.create_task(worker())
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        await asyncio.wait_for(cleaning.wait(), 2)
        for _ in range(cancellations):
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert finished.is_set()
    asyncio.run(scenario())
    event = check_activity.recent(7)[0]
    assert event['status'] == 'UNKNOWN' and event['finished_at']
    assert routes.read_owner(7)['example.com']['state'] == 'queued'


def test_runner_bounds_concurrency_and_runs_with_scheduler_disabled(monkeypatch):
    from sitewatcher.checks import traceroute
    for index in range(4):
        owned(domain=f'{index}.example')
        routes.request_trace(7, f'{index}.example')
    monkeypatch.setattr(routes, 'POLL_SECONDS', 0.01)

    async def scenario():
        running = 0
        maximum = 0
        completed = 0
        all_done = asyncio.Event()

        class Probe:
            def __init__(self, domain):
                pass

            async def run(self):
                nonlocal running, maximum, completed
                running += 1
                maximum = max(maximum, running)
                await asyncio.sleep(0.03)
                running -= 1
                completed += 1
                if completed == 4:
                    all_done.set()
                return CheckOutcome('traceroute', Status.UNKNOWN, 'partial',
                                    {'destination_ip': '192.0.2.1', 'reached': False})
        monkeypatch.setattr(traceroute, 'TracerouteCheck', Probe)
        cfg = AppConfig()
        cfg.scheduler.enabled = False
        async with routes.runner(cfg):
            await asyncio.wait_for(all_done.wait(), 2)
        assert maximum == 2
    asyncio.run(scenario())


def test_hourly_selection_does_not_turn_waiting_auto_jobs_into_manual_jobs():
    owner, domain = owned()
    routes.request_trace(owner, domain)
    age()
    cfg = AppConfig()
    assert routes._candidates(cfg) == [(owner, domain)]
    assert routes.read_owner(owner)[domain]['state'] == 'ready'
    storage.set_domain_override(owner, domain, {'interval_minutes': 0})
    assert not routes._claim(owner, domain, routes._now(), cfg)
    storage.set_domain_override(owner, domain, {'interval_minutes': 5})
    cfg.scheduler.enabled = False
    assert not routes._claim(owner, domain, routes._now(), cfg)
    cfg.scheduler.enabled = True
    assert routes._claim(owner, domain, routes._now(), cfg)


@pytest.mark.parametrize('boundary', ['claim', 'activity'])
def test_cancellation_waits_for_database_threads_before_releasing_job(monkeypatch, boundary):
    import threading
    owned()
    routes.request_trace(7, 'example.com')
    entered = threading.Event()
    release = threading.Event()
    module = routes if boundary == 'claim' else check_activity
    name = '_claim' if boundary == 'claim' else 'start'
    original = getattr(module, name)

    def blocked(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)
    monkeypatch.setattr(module, name, blocked)

    async def scenario():
        task = asyncio.create_task(routes._execute(7, 'example.com'))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
    asyncio.run(scenario())
    assert routes.read_owner(7)['example.com']['state'] == 'queued'
    events = check_activity.recent(7)
    if boundary == 'activity':
        assert events[0]['status'] == 'UNKNOWN' and events[0]['finished_at']
    else:
        assert events == []
