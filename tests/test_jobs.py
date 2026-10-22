import asyncio
from types import SimpleNamespace

from sitewatcher import scheduler, storage
from sitewatcher.bot import jobs
from sitewatcher.bot.jobs import due_checks
from sitewatcher.checks.base import CheckOutcome, Status
from sitewatcher.config import AppConfig, ChecksModel


def test_due_checks_respect_each_interval_and_owner_override(monkeypatch):
    cfg = AppConfig()
    monkeypatch.setattr(storage, "get_domain_override", lambda owner, domain: {"checks": {"ping": False}} if owner == 1 else {})
    monkeypatch.setattr(storage, "last_check_ages", lambda owner, domain: {"http_basic": 4.9, "tls_cert": 200, "whois": 200})

    assert due_checks(cfg, 1, "example.com") == ["ip_change"]
    assert due_checks(cfg, 2, "example.com") == ["ping", "ip_change"]


def test_domain_interval_and_disabled_schedule(monkeypatch):
    cfg = AppConfig()
    monkeypatch.setattr(storage, "last_check_ages", lambda owner, domain: {"http_basic": 9, "ping": 9})
    monkeypatch.setattr(storage, "get_domain_override", lambda owner, domain: {"interval_minutes": 10})

    assert "http_basic" not in due_checks(cfg, 1, "example.com")
    monkeypatch.setattr(storage, "get_domain_override", lambda owner, domain: {"interval_minutes": 0})
    assert due_checks(cfg, 1, "example.com") == []
    assert due_checks(cfg, 1, "example.com", warmup=True) == []


def test_disabled_global_scheduler(monkeypatch):
    cfg = AppConfig()
    cfg.scheduler.enabled = False
    assert due_checks(cfg, 1, "example.com") == []


def test_warmup_sets_baseline_and_next_tick_skips_recent_result(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DEFAULT_DB", tmp_path / "scheduler.db")
    storage.add_domain(1, "example.com")
    cfg = AppConfig()
    cfg.defaults.checks = ChecksModel.model_validate({name: name == "ping" for name in ChecksModel.model_fields})
    ran = []

    class FakeDispatcher:
        def __init__(self, config):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            ran.append(kwargs["only_checks"])
            return [CheckOutcome("ping", Status.OK, "up", {})]

    monkeypatch.setattr(scheduler, "Dispatcher", FakeDispatcher)
    context = SimpleNamespace(application=SimpleNamespace(bot_data={"cfg": cfg}))
    asyncio.run(jobs._run_checks_for_all_domains(context, warmup=True, run_id="warm"))
    asyncio.run(jobs._run_checks_for_all_domains(context, warmup=False, run_id="tick"))

    assert ran == [["ping"]]
    assert storage.get_alert_state(1, "example.com")["last_overall"] == "OK"
    assert len(storage.last_results(1, "example.com")) == 1
    assert storage.last_results(1, "example.com")[0]["source"] == "scheduled"


def test_shared_tick_preserves_owner_pause_concurrency_and_scheduled_history(monkeypatch):
    from sitewatcher import scheduler

    cfg = AppConfig()
    cfg.scheduler.domains_concurrency = 2
    cfg.defaults.checks = ChecksModel.model_validate(
        {name: name == 'ping' for name in ChecksModel.model_fields}
    )
    for owner, domain in [(1, 'one.example'), (1, 'two.example'), (2, 'one.example'),
                          (2, 'paused.example')]:
        storage.add_domain(owner, domain)
    storage.set_domain_override(2, 'paused.example', {'interval_minutes': 0})
    active = 0
    maximum = 0
    received = []

    class Dispatcher:
        def __init__(self, config):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, *, only_checks, use_cache, run_id):
            nonlocal active, maximum
            assert only_checks == ['ping'] and use_cache is False and run_id == 'shared'
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0)
            active -= 1
            return [CheckOutcome('ping', Status.OK, f'owner {owner}', {})]

    async def on_results(owner, domain, results, *, warmup):
        received.append((owner, domain, len(results), warmup))
        assert storage.last_results(owner, domain)[0]['source'] == 'scheduled'

    monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
    asyncio.run(scheduler.run_tick(cfg, warmup=False, on_results=on_results, run_id='shared'))
    assert maximum == 2
    assert sorted(received) == [(1, 'one.example', 1, False), (1, 'two.example', 1, False),
                                (2, 'one.example', 1, False)]
    assert storage.last_results(2, 'paused.example') == []
    assert storage.last_results(1, 'one.example')[0]['message'] == 'owner 1'
    assert storage.last_results(2, 'one.example')[0]['message'] == 'owner 2'


def test_shared_tick_no_resurrection_when_domain_removed_during_probe(monkeypatch):
    from sitewatcher import scheduler

    storage.add_domain(1, 'example.com')
    cfg = AppConfig()

    class Dispatcher:
        def __init__(self, config):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def run_for(self, owner, domain, **kwargs):
            storage.remove_domain(owner, domain)
            return [CheckOutcome('ping', Status.OK, 'up', {})]

    async def on_results(owner, domain, results, *, warmup):
        storage.upsert_alert_state(owner, domain, 'OK', None)

    monkeypatch.setattr(scheduler, 'Dispatcher', Dispatcher)
    asyncio.run(scheduler.run_tick(cfg, warmup=True, on_results=on_results))
    assert storage.list_domains(1) == []
    assert storage.last_results(1, 'example.com') == []
    assert storage.get_alert_state(1, 'example.com') is None
