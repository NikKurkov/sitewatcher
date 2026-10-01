import asyncio
from types import SimpleNamespace

from sitewatcher import storage
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

    monkeypatch.setattr(jobs, "Dispatcher", FakeDispatcher)
    context = SimpleNamespace(application=SimpleNamespace(bot_data={"cfg": cfg}))
    asyncio.run(jobs._run_checks_for_all_domains(context, warmup=True, run_id="warm"))
    asyncio.run(jobs._run_checks_for_all_domains(context, warmup=False, run_id="tick"))

    assert ran == [["ping"]]
    assert storage.get_alert_state(1, "example.com")["last_overall"] == "OK"
    assert len(storage.last_results(1, "example.com")) == 1
