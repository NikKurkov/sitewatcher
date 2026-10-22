"""The unattended worker uses real ticks/storage and never contacts live services."""
import asyncio
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from sitewatcher import scheduler, storage
from sitewatcher.bot import app as bot_app
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig, ChecksModel
from sitewatcher.scheduler_lock import acquire


def config():
    cfg = AppConfig()
    cfg.scheduler.jitter_seconds = 0
    cfg.defaults.checks = ChecksModel.model_validate(
        {name: name == 'ping' for name in ChecksModel.model_fields}
    )
    return cfg


def probes(monkeypatch, status=Status.OK):
    events = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            events.append('open')
            return self

        async def __aexit__(self, *_):
            events.append('close')

        async def run_for(self, owner, domain, **kwargs):
            events.append((owner, domain))
            return [CheckOutcome('ping', status, 'offline' if status == Status.CRIT else 'up', {})]

    monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
    return events


def run_ticks(monkeypatch, cfg, *, sleeps=1, on_sleep=lambda _: None):
    from sitewatcher import worker

    elapsed = 0.0
    delays = []

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz == timezone.utc
            return datetime(2026, 10, 22, 3, 29, tzinfo=timezone.utc) + timedelta(seconds=elapsed)

    async def sleep(delay):
        nonlocal elapsed
        assert delay > 0  # Idle loops must yield; no busy polling.
        delays.append(delay)
        on_sleep(len(delays))
        if len(delays) >= sleeps:
            raise asyncio.CancelledError
        elapsed += delay

    monkeypatch.setattr(worker, 'datetime', Clock)
    monkeypatch.setattr(worker, 'monotonic', lambda: elapsed)
    monkeypatch.setattr(worker, 'sleep', sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker.run_worker(cfg))
    return delays


def test_no_token_records_scheduled_results_and_releases_lifetime_lock(monkeypatch):
    from sitewatcher import worker

    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    storage.add_domain(7, 'example.com')
    events = probes(monkeypatch)

    def no_client(**kwargs):
        pytest.fail('No-token monitoring created a Telegram client')

    monkeypatch.setattr(worker, 'Bot', no_client)

    def verify_tick(_):
        with pytest.raises(RuntimeError, match='already running'):
            with acquire(storage.DEFAULT_DB):
                pass
        rows = storage.last_results(7, 'example.com')
        assert len(rows) == 1 and rows[0]['source'] == 'scheduled' and rows[0]['status'] == 'OK'
        assert storage.get_alert_state(7, 'example.com')['last_overall'] == 'OK'

    run_ticks(monkeypatch, config(), on_sleep=verify_tick)
    assert events.count((7, 'example.com')) == 1 and events[-1] == 'close'
    with acquire(storage.DEFAULT_DB):
        pass
    # Restart respects recent per-check history, preserving baseline and avoiding new probes.
    run_ticks(monkeypatch, config())
    assert events.count((7, 'example.com')) == 1


@pytest.mark.parametrize('mode', ['paused', 'empty', 'disabled'])
def test_idle_worker_still_cleans_history_once_per_utc_day(monkeypatch, mode):
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    cfg = config()
    cfg.history.retention_days = 0
    cfg.history.vacuum_weekly = False
    if mode != 'empty':
        storage.add_domain(7, 'example.com')
        storage.set_domain_override(7, 'example.com', {'interval_minutes': 0})
        with closing(storage._connect()) as connection:
            connection.execute("""INSERT INTO history
                (owner_id,domain,check_name,status,message,created_at)
                VALUES(7,'example.com','ping','OK','old','2000-01-01')""")
    cfg.scheduler.enabled = mode != 'disabled'
    events = probes(monkeypatch)
    cleaned = []
    original_cleanup = storage.cleanup_history

    def cleanup(days):
        cleaned.append(days)
        return original_cleanup(days)

    monkeypatch.setattr(storage, 'cleanup_history', cleanup)
    delays = run_ticks(monkeypatch, cfg, sleeps=4)
    assert (7, 'example.com') not in events
    assert cleaned == [0] and storage.last_results(7, 'example.com') == []
    assert all(delay == 60 for delay in delays)
    with acquire(storage.DEFAULT_DB):
        pass


def test_telegram_outage_retries_saved_incident_then_token_refresh_keeps_state(monkeypatch):
    from sitewatcher import worker

    storage.add_domain(7, 'example.com')
    storage.set_user_alert_chat_id(7, -100)
    storage.upsert_alert_state(7, 'example.com', 'OK', None)
    events = probes(monkeypatch, Status.CRIT)
    instances = []
    sent = []
    contexts = []
    original_results = worker.jobs.process_results

    async def process_results(context, *args, **kwargs):
        contexts.append(context.application.bot_data['alert_deduper'])
        await original_results(context, *args, **kwargs)

    class Bot:
        def __init__(self, *, token, **kwargs):
            self.token = token
            self.closed = False
            instances.append(self)

        async def initialize(self):
            pass

        async def shutdown(self):
            self.closed = True

        async def send_message(self, **kwargs):
            if self.token == '123:outage':
                raise RuntimeError('offline')
            sent.append(kwargs)

    monkeypatch.setenv('TELEGRAM_TOKEN', '123:outage')
    monkeypatch.setattr(worker, 'Bot', Bot)
    monkeypatch.setattr(worker.jobs, 'process_results', process_results)

    def boundary(number):
        if number == 1:
            assert storage.get_alert_state(7, 'example.com')['last_overall'] == 'OK'
            monkeypatch.setenv('TELEGRAM_TOKEN', '456:working')
        else:
            assert storage.get_alert_state(7, 'example.com')['last_overall'] == 'CRIT'

    run_ticks(monkeypatch, config(), sleeps=3, on_sleep=boundary)
    assert len(sent) == 1 and sent[0]['chat_id'] == -100 and 'CRIT' in sent[0]['text']
    assert events.count((7, 'example.com')) == 1
    assert len(instances) == 2 and all(bot.closed for bot in instances)
    assert contexts and all(item is contexts[0] for item in contexts)


def test_bad_token_initialization_does_not_stop_monitoring_or_leak_client(monkeypatch):
    from sitewatcher import worker

    storage.add_domain(7, 'example.com')
    probes(monkeypatch)
    closed = []

    class Bot:
        def __init__(self, **kwargs):
            pass

        async def initialize(self):
            raise RuntimeError('token-bearing error must not escape')

        async def shutdown(self):
            closed.append(True)

    monkeypatch.setattr(worker, 'Bot', Bot)
    monkeypatch.setenv('TELEGRAM_TOKEN', '123:invalid')
    run_ticks(monkeypatch, config())
    assert storage.last_results(7, 'example.com')[0]['source'] == 'scheduled'
    assert closed


def test_bot_and_worker_cannot_start_together(monkeypatch):
    from sitewatcher import worker

    monkeypatch.setenv('TELEGRAM_TOKEN', '123:offline')
    monkeypatch.setattr(bot_app, '_run_polling', lambda *_: pytest.fail('Busy bot polled'))
    with acquire(storage.DEFAULT_DB):
        with pytest.raises(RuntimeError, match='already running'):
            asyncio.run(worker.run_worker(config()))
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)

    def launch_bot(_):
        monkeypatch.setenv('TELEGRAM_TOKEN', '123:offline')
        with pytest.raises(RuntimeError, match='already running'):
            bot_app.run_bot(config())

    run_ticks(monkeypatch, config(), on_sleep=launch_bot)


def test_cancellation_during_probe_closes_dispatcher_and_telegram_before_unlock(monkeypatch):
    from sitewatcher import worker

    storage.add_domain(7, 'example.com')
    closed = []

    class Dispatcher:
        def __init__(self, cfg):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            closed.append('dispatcher')

        async def run_for(self, *args, **kwargs):
            raise asyncio.CancelledError

    class Bot:
        def __init__(self, **kwargs):
            pass

        async def initialize(self):
            pass

        async def shutdown(self):
            with pytest.raises(RuntimeError, match='already running'):
                with acquire(storage.DEFAULT_DB):
                    pass
            closed.append('telegram')

    monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
    monkeypatch.setattr(worker, 'Bot', Bot)
    monkeypatch.setenv('TELEGRAM_TOKEN', '123:offline')
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker.run_worker(config()))
    assert closed == ['dispatcher', 'telegram']
    with acquire(storage.DEFAULT_DB):
        pass


def test_cli_worker_runs_without_token(monkeypatch):
    from sitewatcher import main, worker

    invoked = []

    async def run_worker(cfg):
        invoked.append(cfg.scheduler.enabled)

    monkeypatch.setattr(worker, 'run_worker', run_worker)
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    monkeypatch.setattr('sys.argv', ['sitewatcher', 'worker'])
    main.main()
    assert invoked == [True]


def test_cli_sigterm_closes_active_probe_and_releases_ownership(tmp_path):
    import os
    import selectors
    import signal
    import subprocess
    import sys
    import textwrap

    code = textwrap.dedent('''
        import asyncio
        import os
        import sys
        from pathlib import Path
        from sitewatcher import main, scheduler, storage
        os.environ.pop('TELEGRAM_TOKEN', None)
        storage.DEFAULT_DB = Path(sys.argv[1])
        storage.add_domain(7, 'example.com')
        class Dispatcher:
            def __init__(self, cfg): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *_): print('CLOSED', flush=True)
            async def run_for(self, *args, **kwargs):
                print('READY', flush=True)
                await asyncio.Event().wait()
        scheduler.Dispatcher = Dispatcher
        main.load_config = lambda *_: main.AppConfig(scheduler={'jitter_seconds': 0})
        sys.argv = ['sitewatcher', 'worker']
        main.main()
        print('STOPPED', flush=True)
    ''')
    database = tmp_path / 'sigterm.db'
    process = subprocess.Popen([sys.executable, '-c', code, str(database)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=5)
        output = ''
        while 'READY' not in output:
            line = process.stdout.readline()
            assert line, process.stderr.read()
            output += line
        os.kill(process.pid, signal.SIGTERM)
        output, error = process.communicate(timeout=5)
        assert process.returncode == 0, error
        assert 'CLOSED' in output and 'STOPPED' in output
        with acquire(database):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def test_slow_startup_warmup_finishes_before_regular_tick(monkeypatch):
    from sitewatcher import worker

    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    storage.add_domain(7, 'example.com')
    called = []

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()

        class Dispatcher:
            def __init__(self, cfg):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                pass

            async def run_for(self, owner, domain, **kwargs):
                called.append(domain)
                started.set()
                await release.wait()
                return [CheckOutcome('ping', Status.CRIT, 'offline', {})]

        async def stop_after_warmup(delay):
            assert storage.get_alert_state(7, 'example.com')['last_overall'] == 'CRIT'
            raise asyncio.CancelledError

        monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
        monkeypatch.setattr(worker, 'sleep', stop_after_warmup)
        task = asyncio.create_task(worker.run_worker(config()))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            await asyncio.sleep(0)
            assert called == ['example.com'] and storage.last_results(7, 'example.com') == []
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert called == ['example.com']
        assert len(storage.last_results(7, 'example.com')) == 1

    asyncio.run(scenario())


def test_new_private_token_is_loaded_and_invalid_replacement_revokes_client(monkeypatch):
    from sitewatcher import worker
    from sitewatcher.telegram_connection import save_bot_token, token_path

    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    storage.add_domain(7, 'example.com')
    storage.set_user_alert_chat_id(7, -100)
    storage.upsert_alert_state(7, 'example.com', 'OK', None)
    events = probes(monkeypatch, Status.CRIT)
    instances = []
    sent = []

    class Bot:
        def __init__(self, *, token, **kwargs):
            self.closed = False
            instances.append(self)

        async def initialize(self):
            pass

        async def shutdown(self):
            self.closed = True

        async def send_message(self, **kwargs):
            sent.append(kwargs)

    monkeypatch.setattr(worker, 'Bot', Bot)
    cfg = config()
    cfg.alerts.policy = 'all'
    cfg.alerts.cooldown_sec = 0

    def boundary(number):
        if number == 1:
            assert instances == [] and sent == []
            save_bot_token('123:' + 'A' * 20)
        elif number == 2:
            assert len(sent) == 1
            token_path().chmod(0o644)
        else:
            assert len(sent) == 1 and instances[0].closed

    run_ticks(monkeypatch, cfg, sleeps=3, on_sleep=boundary)
    assert len(instances) == 1 and events.count((7, 'example.com')) == 1


def test_maintenance_runs_on_each_utc_day_even_with_long_tick_interval(monkeypatch):
    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    cfg = config()
    cfg.scheduler.interval_minutes = 2880
    cfg.alerts.cooldown_sec = 172800
    cfg.history.vacuum_weekly = False
    cleaned = []
    monkeypatch.setattr(storage, 'cleanup_history', lambda days: cleaned.append(days) or 0)
    delays = run_ticks(monkeypatch, cfg, sleeps=3)
    assert delays == [60, 86400, 86340]
    assert cleaned == [30, 30]


def test_cancelling_during_sqlite_cleanup_retains_lock_until_thread_finishes(monkeypatch):
    import threading
    from sitewatcher import worker

    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    started = threading.Event()
    release = threading.Event()
    finished = []

    def cleanup(days):
        started.set()
        assert release.wait(timeout=3)
        finished.append(True)
        return 0

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 22, 3, 30, tzinfo=timezone.utc)

    monkeypatch.setattr(worker, 'datetime', Clock)
    monkeypatch.setattr(storage, 'cleanup_history', cleanup)

    async def scenario():
        task = asyncio.create_task(worker.run_worker(config()))
        try:
            assert await asyncio.to_thread(started.wait, 1)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            with pytest.raises(RuntimeError, match='already running'):
                with acquire(storage.DEFAULT_DB):
                    pass
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=3)
        assert finished == [True]
        with acquire(storage.DEFAULT_DB):
            pass

    asyncio.run(scenario())


def test_shutdown_waits_for_every_concurrent_probe_before_unlock(monkeypatch):
    from sitewatcher import worker

    monkeypatch.delenv('TELEGRAM_TOKEN', raising=False)
    for domain in ['fast.example', 'slow.example']:
        storage.add_domain(7, domain)

    async def scenario():
        started = []
        cleaning = asyncio.Event()
        release = asyncio.Event()
        finished = asyncio.Event()
        closed = []

        class Dispatcher:
            def __init__(self, cfg):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                closed.append(True)

            async def run_for(self, owner, domain, **kwargs):
                started.append(domain)
                try:
                    await asyncio.Event().wait()
                finally:
                    if domain == 'slow.example':
                        cleaning.set()
                        await release.wait()
                        finished.set()

        monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
        task = asyncio.create_task(worker.run_worker(config()))
        try:
            while len(started) < 2:
                await asyncio.sleep(0)
            task.cancel()
            await asyncio.wait_for(cleaning.wait(), timeout=1)
            # Give the fast probe and gather callbacks time to unwind independently.
            for _ in range(5):
                await asyncio.sleep(0)
            assert not task.done() and closed == []
            with pytest.raises(RuntimeError, match='already running'):
                with acquire(storage.DEFAULT_DB):
                    pass
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(finished.wait(), timeout=1)
        assert closed == [True]
        with acquire(storage.DEFAULT_DB):
            pass

    asyncio.run(scenario())
